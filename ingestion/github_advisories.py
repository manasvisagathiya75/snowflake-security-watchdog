"""Fetches security advisories from the GitHub GraphQL API and REST API."""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Generator

import requests

logger = logging.getLogger(__name__)

_GRAPHQL_URL = "https://api.github.com/graphql"
_REST_URL = "https://api.github.com/advisories"

_ADVISORY_QUERY = """
query($cursor: String, $updatedSince: DateTime) {
  securityAdvisories(
    first: 100
    after: $cursor
    updatedSince: $updatedSince
    orderBy: { field: UPDATED_AT, direction: ASC }
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      withdrawnAt
      identifiers { type value }
      references { url }
      cvss { score vectorString }
      cwes(first: 10) { nodes { cweId name } }
      vulnerabilities(first: 20) {
        nodes {
          package { name ecosystem }
          severity
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
"""


class GitHubAdvisoryFetcher:
    def __init__(self, token: str) -> None:
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        })

    def _query(self, cursor: str | None, updated_since: str | None) -> dict:
        resp = self._session.post(
            _GRAPHQL_URL,
            json={
                "query": _ADVISORY_QUERY,
                "variables": {"cursor": cursor, "updatedSince": updated_since},
            },
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body:
            raise RuntimeError(f"GitHub GraphQL errors: {body['errors']}")
        return body["data"]["securityAdvisories"]

    def fetch_all(
        self, updated_since: str | None = None
    ) -> Generator[dict, None, None]:
        """Yield every advisory, paginating automatically.

        Args:
            updated_since: ISO 8601 datetime string; only advisories updated
                after this timestamp are returned.
        """
        cursor: str | None = None
        page = 0
        fetched_at = datetime.now(timezone.utc).isoformat()

        while True:
            page += 1
            result = self._query(cursor=cursor, updated_since=updated_since)
            nodes = result["nodes"]
            logger.info("GitHub page %d: %d advisories", page, len(nodes))

            for node in nodes:
                node["_fetched_at"] = fetched_at
                yield node

            if not result["pageInfo"]["hasNextPage"]:
                break
            cursor = result["pageInfo"]["endCursor"]
            # GitHub GraphQL rate limit: 5 000 points/hour; each call costs ~1 point.
            time.sleep(0.5)

    def fetch_batch(self, updated_since: str | None = None) -> list[dict]:
        return list(self.fetch_all(updated_since=updated_since))

    # ------------------------------------------------------------------
    # REST API: filtered, flattened records for RAW_GITHUB_ADVISORIES
    # ------------------------------------------------------------------

    def _flatten(self, adv: dict, fetched_at: str) -> dict:
        cvss = adv.get("cvss") or {}
        credits_list = adv.get("credits") or []
        vulns = adv.get("vulnerabilities") or []
        cwes = adv.get("cwes") or []
        return {
            "GHSA_ID": adv.get("ghsa_id"),
            "CVE_ID": adv.get("cve_id"),
            "SUMMARY": (adv.get("summary") or "")[:2000],
            "DESCRIPTION": adv.get("description"),
            "SEVERITY": adv.get("severity"),
            "CVSS_SCORE": cvss.get("score"),
            "CVSS_VECTOR_STRING": cvss.get("vector_string"),
            "CWES": json.dumps(cwes),
            "AFFECTED_PACKAGES": json.dumps(vulns),
            "PUBLISHED_AT": adv.get("published_at"),
            "UPDATED_AT": adv.get("updated_at"),
            "WITHDRAWN_AT": adv.get("withdrawn_at"),
            "HTML_URL": adv.get("html_url"),
            "CREDITS_COUNT": len(credits_list),
            "SOURCE_API": "github_rest",
            "INGESTED_AT": fetched_at,
            "RAW_JSON": json.dumps(adv, default=str),
        }

    def fetch_and_flatten(
        self,
        ecosystems: list[str],
        severities: list[str],
        max_pages_per_call: int = 5,
        since: str | None = None,
    ) -> list[dict]:
        """Fetch REST advisories filtered by ecosystem/severity; return flat records.

        Paginates up to max_pages_per_call pages per ecosystem and deduplicates
        across ecosystems by GHSA ID.
        """
        seen: set[str] = set()
        records: list[dict] = []
        fetched_at = datetime.now(timezone.utc).isoformat()
        severity_set = {s.lower() for s in severities}

        for ecosystem in ecosystems:
            params: dict = {"ecosystem": ecosystem.lower(), "per_page": 100}
            if since:
                params["updated"] = since

            for page in range(1, max_pages_per_call + 1):
                params["page"] = page
                resp = self._session.get(_REST_URL, params=params, timeout=30)
                resp.raise_for_status()
                batch = resp.json()
                if not batch:
                    break

                kept = 0
                for adv in batch:
                    if (adv.get("severity") or "").lower() not in severity_set:
                        continue
                    ghsa_id = adv.get("ghsa_id", "")
                    if ghsa_id in seen:
                        continue
                    seen.add(ghsa_id)
                    records.append(self._flatten(adv, fetched_at))
                    kept += 1

                logger.info(
                    "ecosystem=%-6s  page=%d/%d  returned=%d  kept=%d",
                    ecosystem, page, max_pages_per_call, len(batch), kept,
                )
                if len(batch) < 100:
                    break

            time.sleep(0.3)

        return records
