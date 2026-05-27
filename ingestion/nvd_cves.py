"""Fetches CVE records from the NIST NVD REST API v2.0."""

import logging
import time
from datetime import datetime, timezone
from typing import Generator

import requests

logger = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000


class NVDFetcher:
    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key
        self._session = requests.Session()
        if api_key:
            self._session.headers["apiKey"] = api_key
        # NVD rate limits: 5 req/30 s without key, 50 req/30 s with key.
        self._delay = 0.6 if api_key else 6.0

    def _get(self, params: dict) -> dict:
        resp = self._session.get(_NVD_URL, params=params, timeout=60)
        if resp.status_code == 403:
            logger.warning("NVD rate limit hit; sleeping 30 s")
            time.sleep(30)
            resp = self._session.get(_NVD_URL, params=params, timeout=60)
        resp.raise_for_status()
        time.sleep(self._delay)
        return resp.json()

    def fetch_all(
        self,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
        last_mod_start_date: str | None = None,
        last_mod_end_date: str | None = None,
    ) -> Generator[dict, None, None]:
        """Yield every CVE record, paginating automatically.

        Date parameters must use the format ``YYYY-MM-DDTHH:MM:SS.000+00:00``.
        Supply ``last_mod_start_date`` / ``last_mod_end_date`` for incremental
        loads; supply ``pub_start_date`` / ``pub_end_date`` for publication-date
        filters.
        """
        params: dict = {"resultsPerPage": _PAGE_SIZE, "startIndex": 0}
        for key, val in {
            "pubStartDate": pub_start_date,
            "pubEndDate": pub_end_date,
            "lastModStartDate": last_mod_start_date,
            "lastModEndDate": last_mod_end_date,
        }.items():
            if val:
                params[key] = val

        fetched_at = datetime.now(timezone.utc).isoformat()
        total: int | None = None
        start_index = 0

        while True:
            params["startIndex"] = start_index
            data = self._get(params)

            if total is None:
                total = data["totalResults"]
                logger.info("NVD total results: %d", total)

            vulnerabilities: list[dict] = data.get("vulnerabilities", [])
            logger.info(
                "NVD records %d–%d / %d",
                start_index,
                start_index + len(vulnerabilities),
                total,
            )

            for item in vulnerabilities:
                # NVD wraps each CVE: {"cve": {...}}
                cve: dict = item.get("cve", item)
                cve["_fetched_at"] = fetched_at
                yield cve

            start_index += len(vulnerabilities)
            if not vulnerabilities or start_index >= (total or 0):
                break

    def fetch_batch(self, **kwargs) -> list[dict]:
        return list(self.fetch_all(**kwargs))
