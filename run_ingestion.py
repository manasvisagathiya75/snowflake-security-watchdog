#!/usr/bin/env python3
"""CLI entry point for the full Cloud Security Intelligence pipeline."""

import argparse
import contextlib
import logging
import os
import sys
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

from ingestion.github_advisories import GitHubAdvisoryFetcher
from ingestion.load_to_snowflake import SnowflakeLoader
from ingestion.nvd_cves import NVDFetcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


@contextlib.contextmanager
def _step(name: str):
    """Log step start/end/duration; re-raise on failure."""
    t0 = time.time()
    print(f"\n{'-'*60}")
    print(f"  STEP: {name}")
    print(f"{'-'*60}")
    try:
        yield
        print(f"  OK  {name} -- {time.time() - t0:.1f}s")
    except Exception as exc:
        print(f"  FAIL {name}: {exc}")
        raise


def _build_loader() -> SnowflakeLoader:
    return SnowflakeLoader(
        account=os.environ["SNOWFLAKE_ACCOUNT"],
        user=os.environ["SNOWFLAKE_USER"],
        private_key_path=os.environ["SNOWFLAKE_PRIVATE_KEY_PATH"],
        private_key_passphrase=os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE") or None,
        database=os.getenv("SNOWFLAKE_DATABASE", "ANALYTICS"),
        warehouse=os.environ["SNOWFLAKE_WAREHOUSE"],
        role=os.getenv("SNOWFLAKE_ROLE") or None,
    )


def run_github(loader: SnowflakeLoader, since: str | None) -> None:
    t0 = time.time()
    fetcher    = GitHubAdvisoryFetcher(token=os.environ["GITHUB_TOKEN"])
    ecosystems = ["pip", "npm", "go", "maven"]
    severities = ["critical", "high"]
    print(f"  ecosystems : {', '.join(ecosystems)}")
    print(f"  severities : {', '.join(severities)}")
    print(f"  max pages  : 2 per ecosystem")
    if since:
        print(f"  since      : {since}")
    records = fetcher.fetch_and_flatten(
        ecosystems=ecosystems, severities=severities,
        max_pages_per_call=2, since=since,
    )
    print(f"  Fetched {len(records)} records in {time.time() - t0:.1f}s")
    loaded = loader.upsert_raw_github_advisories(records)
    print(f"  Loaded  {loaded} records -> ANALYTICS.RAW.RAW_GITHUB_ADVISORIES")


def run_nvd(loader: SnowflakeLoader, since: str | None) -> None:
    t0      = time.time()
    fetcher = NVDFetcher(api_key=os.getenv("NVD_API_KEY") or None)
    kwargs: dict = {}
    if since:
        kwargs["last_mod_start_date"] = f"{since}T00:00:00.000+00:00"
        kwargs["last_mod_end_date"]   = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000+00:00"
        )
    label = f" since {since}" if since else " (full load)"
    print(f"  Fetching NVD CVEs{label} ...")
    records = fetcher.fetch_batch(**kwargs)
    print(f"  Fetched {len(records)} records in {time.time() - t0:.1f}s")
    loaded = loader.upsert_nvd_cves(records)
    print(f"  Loaded  {loaded} records -> ANALYTICS.RAW.NVD_CVES_RAW")


def main() -> None:
    load_dotenv()
    t_start = time.time()

    parser = argparse.ArgumentParser(
        description="Cloud Security Intelligence full pipeline."
    )
    parser.add_argument(
        "--source", choices=["github", "nvd", "all"], default="all",
        help="Data source to ingest (default: all)",
    )
    parser.add_argument(
        "--since", metavar="YYYY-MM-DD",
        help="Incremental load: only fetch records updated on or after this date",
    )
    parser.add_argument(
        "--skip-brief", action="store_true",
        help="Skip threat brief generation",
    )
    parser.add_argument(
        "--skip-drift", action="store_true",
        help="Skip Terraform drift detection",
    )
    args = parser.parse_args()

    # ── Step 1 & 2: Ingest raw data ───────────────────────────────────────────
    with _step("Ingest & Load RAW"):
        with _build_loader() as loader:
            if args.source in ("github", "all"):
                run_github(loader, args.since)
            if args.source in ("nvd", "all"):
                run_nvd(loader, args.since)

    # ── Step 3: Snowpark anomaly detection ────────────────────────────────────
    with _step("Snowpark Anomaly Detection"):
        from ingestion.anomaly_detection import run_anomaly_detection
        run_anomaly_detection()

    # ── Step 4: Threat brief ──────────────────────────────────────────────────
    if not args.skip_brief:
        with _step("Threat Brief Generation"):
            from ingestion.threat_summarizer import generate_threat_brief
            generate_threat_brief()
    else:
        print("\n[SKIPPED] Threat brief generation (--skip-brief)")

    # ── Step 5: Terraform drift detection ─────────────────────────────────────
    if not args.skip_drift:
        with _step("Terraform Drift Detection"):
            from ingestion.drift_detector import run_drift_detection
            run_drift_detection()
    else:
        print("\n[SKIPPED] Terraform drift detection (--skip-drift)")

    total = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"  Pipeline complete -- total time: {total:.1f}s")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
