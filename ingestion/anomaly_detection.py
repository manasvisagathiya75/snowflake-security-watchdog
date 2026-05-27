"""Snowpark-based statistical anomaly detection on vulnerability risk scores."""

import logging
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, Encoding, PrivateFormat, NoEncryption,
)

logger = logging.getLogger(__name__)


def _private_key_der(path: str) -> bytes:
    with open(path, "rb") as f:
        key = load_pem_private_key(f.read(), password=None)
    return key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())


def run_anomaly_detection() -> int:
    """Detect statistical outliers in vulnerability risk scores via Snowpark.

    Groups MART_VULNERABILITY_SUMMARY by VULNERABILITY_CATEGORY, computes
    per-category mean and stddev of AVG_COMPOSITE_RISK_SCORE using window
    functions, flags rows where |z_score| > 2, writes to
    ANALYTICS.SECURITY.VULNERABILITY_ANOMALIES.

    Returns the number of anomalies written.
    """
    load_dotenv()

    from snowflake.snowpark import Session

    session = Session.builder.configs({
        "account":     os.environ["SNOWFLAKE_ACCOUNT"],
        "user":        os.environ["SNOWFLAKE_USER"],
        "private_key": _private_key_der(os.environ["SNOWFLAKE_PRIVATE_KEY_PATH"]),
        "role":        "ACCOUNTADMIN",
        "warehouse":   os.environ["SNOWFLAKE_WAREHOUSE"],
        "database":    "ANALYTICS",
        "schema":      "MARTS",
    }).create()

    try:
        # ── Ensure SECURITY schema and target table exist ─────────────────────
        session.sql("CREATE SCHEMA IF NOT EXISTS ANALYTICS.SECURITY").collect()
        logger.info("ANALYTICS.SECURITY schema ready")

        session.sql("""
            CREATE TABLE IF NOT EXISTS ANALYTICS.SECURITY.VULNERABILITY_ANOMALIES (
                ADVISORY_ID          VARCHAR(200),
                ECOSYSTEM            VARCHAR(100),
                COMPOSITE_RISK_SCORE FLOAT,
                ECOSYSTEM_MEAN       FLOAT,
                ECOSYSTEM_STDDEV     FLOAT,
                Z_SCORE              FLOAT,
                ANOMALY_TYPE         VARCHAR(50),
                DETECTED_AT          TIMESTAMP_TZ
            )
        """).collect()
        logger.info("ANALYTICS.SECURITY.VULNERABILITY_ANOMALIES table ready")

        # ── Compute Z-scores and detect anomalies in pure SQL ─────────────────
        anomaly_sql = """
            WITH base AS (
                SELECT
                    SEVERITY,
                    AGE_BUCKET,
                    VULNERABILITY_CATEGORY,
                    AVG_COMPOSITE_RISK_SCORE
                FROM ANALYTICS.MARTS.MART_VULNERABILITY_SUMMARY
            ),
            with_stats AS (
                SELECT
                    *,
                    AVG(AVG_COMPOSITE_RISK_SCORE)    OVER (PARTITION BY VULNERABILITY_CATEGORY) AS ECOSYSTEM_MEAN,
                    STDDEV(AVG_COMPOSITE_RISK_SCORE) OVER (PARTITION BY VULNERABILITY_CATEGORY) AS ECOSYSTEM_STDDEV
                FROM base
            ),
            with_zscore AS (
                SELECT
                    *,
                    CASE
                        WHEN ECOSYSTEM_STDDEV IS NULL OR ECOSYSTEM_STDDEV = 0 THEN 0.0
                        ELSE (AVG_COMPOSITE_RISK_SCORE - ECOSYSTEM_MEAN) / ECOSYSTEM_STDDEV
                    END AS Z_SCORE
                FROM with_stats
            )
            SELECT
                SEVERITY || '_' || AGE_BUCKET || '_' || VULNERABILITY_CATEGORY AS ADVISORY_ID,
                VULNERABILITY_CATEGORY                                           AS ECOSYSTEM,
                AVG_COMPOSITE_RISK_SCORE                                         AS COMPOSITE_RISK_SCORE,
                ECOSYSTEM_MEAN,
                ECOSYSTEM_STDDEV,
                Z_SCORE,
                'statistical_outlier'                                            AS ANOMALY_TYPE,
                CURRENT_TIMESTAMP()::TIMESTAMP_TZ                                AS DETECTED_AT
            FROM with_zscore
            WHERE ABS(Z_SCORE) > 2.0
            ORDER BY ABS(Z_SCORE) DESC
        """

        anomalies = session.sql(anomaly_sql).collect()
        row_count  = len(anomalies)

        # ── Write anomalies ───────────────────────────────────────────────────
        if row_count > 0:
            # Use INSERT via SQL to avoid write_pandas schema-detection issues
            insert_sql = """
                INSERT INTO ANALYTICS.SECURITY.VULNERABILITY_ANOMALIES
                    (ADVISORY_ID, ECOSYSTEM, COMPOSITE_RISK_SCORE,
                     ECOSYSTEM_MEAN, ECOSYSTEM_STDDEV, Z_SCORE,
                     ANOMALY_TYPE, DETECTED_AT)
                SELECT
                    ADVISORY_ID, ECOSYSTEM, COMPOSITE_RISK_SCORE,
                    ECOSYSTEM_MEAN, ECOSYSTEM_STDDEV, Z_SCORE,
                    ANOMALY_TYPE, DETECTED_AT
                FROM (
            """ + anomaly_sql + "\n)"
            session.sql(insert_sql).collect()

            print(f"\nStatistical anomalies detected: {row_count}")
            print("─" * 50)
            # Summarise per ecosystem
            ecosystem_counts: dict[str, int] = {}
            for row in anomalies:
                eco = row["ECOSYSTEM"]
                ecosystem_counts[eco] = ecosystem_counts.get(eco, 0) + 1
            for eco, cnt in sorted(ecosystem_counts.items(), key=lambda x: -x[1]):
                print(f"  {eco:<30} {cnt} anomaly(ies)")
        else:
            print("\nNo anomalies detected -- all z-scores within +/-2 sigma")

        return row_count

    finally:
        session.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    run_anomaly_detection()
