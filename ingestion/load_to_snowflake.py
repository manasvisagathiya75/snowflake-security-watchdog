"""Snowflake loader using key-pair auth and a staging-table MERGE upsert pattern."""

import json
import logging
from pathlib import Path
from typing import Callable

import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from snowflake.connector.pandas_tools import write_pandas
import snowflake.connector

logger = logging.getLogger(__name__)


def _private_key_bytes(path: str, passphrase: str | None = None) -> bytes:
    """Read a PEM private key and return DER bytes for the Snowflake connector."""
    pem = Path(path).read_bytes()
    key = serialization.load_pem_private_key(
        pem,
        password=passphrase.encode() if passphrase else None,
        backend=default_backend(),
    )
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


class SnowflakeLoader:
    def __init__(
        self,
        account: str,
        user: str,
        private_key_path: str,
        database: str,
        warehouse: str,
        role: str | None = None,
        private_key_passphrase: str | None = None,
    ) -> None:
        self._database = database
        self.conn = snowflake.connector.connect(
            account=account,
            user=user,
            private_key=_private_key_bytes(private_key_path, private_key_passphrase),
            database=database,
            warehouse=warehouse,
            role=role,
            session_parameters={"QUERY_TAG": "security_watchdog_ingestion"},
        )

    # ------------------------------------------------------------------
    # Schema / table setup
    # ------------------------------------------------------------------

    def ensure_raw_tables(self) -> None:
        """Create RAW schema tables if they don't already exist."""
        ddls = [
            """
            CREATE TABLE IF NOT EXISTS RAW.GITHUB_ADVISORIES_RAW (
                GHSA_ID    VARCHAR(50)   NOT NULL,
                RECORD     VARIANT       NOT NULL,
                FETCHED_AT TIMESTAMP_TZ  NOT NULL,
                LOADED_AT  TIMESTAMP_TZ  NOT NULL DEFAULT CURRENT_TIMESTAMP(),
                CONSTRAINT pk_github_advisories PRIMARY KEY (GHSA_ID)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS RAW.NVD_CVES_RAW (
                CVE_ID     VARCHAR(50)   NOT NULL,
                RECORD     VARIANT       NOT NULL,
                FETCHED_AT TIMESTAMP_TZ  NOT NULL,
                LOADED_AT  TIMESTAMP_TZ  NOT NULL DEFAULT CURRENT_TIMESTAMP(),
                CONSTRAINT pk_nvd_cves PRIMARY KEY (CVE_ID)
            )
            """,
        ]
        with self.conn.cursor() as cur:
            for ddl in ddls:
                cur.execute(ddl)
        logger.info("RAW tables verified / created")

    # ------------------------------------------------------------------
    # Internal upsert helper
    # ------------------------------------------------------------------

    def _stage_and_merge(
        self,
        records: list[dict],
        stage_table: str,
        target_table: str,
        id_col: str,
        id_func: Callable[[dict], str],
    ) -> int:
        """Bulk-load records into a temp staging table, then MERGE into target.

        Uses write_pandas for the bulk upload to avoid row-by-row round trips.
        """
        if not records:
            return 0

        df = pd.DataFrame(
            [
                {
                    "ID": id_func(r),
                    "RECORD_JSON": json.dumps(r, default=str),
                    "FETCHED_AT": r["_fetched_at"],
                }
                for r in records
            ]
        )

        with self.conn.cursor() as cur:
            cur.execute("USE SCHEMA RAW")
            cur.execute(
                f"CREATE OR REPLACE TEMPORARY TABLE {stage_table} "
                f"(ID VARCHAR(100), RECORD_JSON VARCHAR, FETCHED_AT VARCHAR)"
            )

        write_pandas(
            self.conn,
            df,
            stage_table,
            database=self._database,
            schema="RAW",
            auto_create_table=False,
            overwrite=False,
        )

        with self.conn.cursor() as cur:
            cur.execute(f"""
                MERGE INTO RAW.{target_table} AS tgt
                USING (
                    SELECT ID,
                           PARSE_JSON(RECORD_JSON) AS RECORD,
                           FETCHED_AT::TIMESTAMP_TZ AS FETCHED_AT
                    FROM   RAW.{stage_table}
                ) AS src ON tgt.{id_col} = src.ID
                WHEN MATCHED THEN UPDATE SET
                    RECORD     = src.RECORD,
                    FETCHED_AT = src.FETCHED_AT,
                    LOADED_AT  = CURRENT_TIMESTAMP()
                WHEN NOT MATCHED THEN INSERT ({id_col}, RECORD, FETCHED_AT)
                    VALUES (src.ID, src.RECORD, src.FETCHED_AT)
            """)

        logger.info("Merged %d records into RAW.%s", len(records), target_table)
        return len(records)

    # ------------------------------------------------------------------
    # Public upsert methods
    # ------------------------------------------------------------------

    def upsert_github_advisories(self, records: list[dict]) -> int:
        return self._stage_and_merge(
            records,
            stage_table="GITHUB_ADVISORIES_STAGE",
            target_table="GITHUB_ADVISORIES_RAW",
            id_col="GHSA_ID",
            id_func=lambda r: r["ghsaId"],
        )

    def upsert_raw_github_advisories(self, records: list[dict]) -> int:
        """Upsert flattened records into ANALYTICS.RAW.RAW_GITHUB_ADVISORIES.

        Uses a VARCHAR staging table so write_pandas avoids VARIANT/TIMESTAMP
        type inference issues; MERGE applies PARSE_JSON and TRY_TO_TIMESTAMP_TZ.
        """
        if not records:
            return 0

        rows = [
            {
                "GHSA_ID": r["GHSA_ID"],
                "CVE_ID": r.get("CVE_ID"),
                "SUMMARY": r.get("SUMMARY"),
                "DESCRIPTION": r.get("DESCRIPTION"),
                "SEVERITY": r.get("SEVERITY"),
                "CVSS_SCORE": r.get("CVSS_SCORE"),          # float | None
                "CVSS_VECTOR_STRING": r.get("CVSS_VECTOR_STRING"),
                "CWES_JSON": r.get("CWES"),                  # JSON string
                "AFFECTED_PACKAGES_JSON": r.get("AFFECTED_PACKAGES"),
                "PUBLISHED_AT": r.get("PUBLISHED_AT"),       # ISO string
                "UPDATED_AT": r.get("UPDATED_AT"),
                "WITHDRAWN_AT": r.get("WITHDRAWN_AT"),
                "HTML_URL": r.get("HTML_URL"),
                "CREDITS_COUNT": r.get("CREDITS_COUNT", 0),  # int
                "SOURCE_API": r.get("SOURCE_API"),
                "INGESTED_AT": r.get("INGESTED_AT"),
                "RAW_JSON_STR": r.get("RAW_JSON"),           # JSON string
            }
            for r in records
        ]
        df = pd.DataFrame(rows)

        with self.conn.cursor() as cur:
            cur.execute("USE SCHEMA RAW")
            cur.execute("""
                CREATE OR REPLACE TEMPORARY TABLE TMP_GITHUB_RAW_STAGE (
                    GHSA_ID                VARCHAR,
                    CVE_ID                 VARCHAR,
                    SUMMARY                VARCHAR,
                    DESCRIPTION            VARCHAR,
                    SEVERITY               VARCHAR,
                    CVSS_SCORE             FLOAT,
                    CVSS_VECTOR_STRING     VARCHAR,
                    CWES_JSON              VARCHAR,
                    AFFECTED_PACKAGES_JSON VARCHAR,
                    PUBLISHED_AT           VARCHAR,
                    UPDATED_AT             VARCHAR,
                    WITHDRAWN_AT           VARCHAR,
                    HTML_URL               VARCHAR,
                    CREDITS_COUNT          INTEGER,
                    SOURCE_API             VARCHAR,
                    INGESTED_AT            VARCHAR,
                    RAW_JSON_STR           VARCHAR
                )
            """)

        write_pandas(
            self.conn, df, "TMP_GITHUB_RAW_STAGE",
            database=self._database, schema="RAW",
            auto_create_table=False, overwrite=False,
        )

        with self.conn.cursor() as cur:
            cur.execute("""
                MERGE INTO RAW.RAW_GITHUB_ADVISORIES AS tgt
                USING (
                    SELECT
                        GHSA_ID,
                        CVE_ID,
                        SUMMARY,
                        DESCRIPTION,
                        SEVERITY,
                        CVSS_SCORE,
                        CVSS_VECTOR_STRING,
                        PARSE_JSON(CWES_JSON)              AS CWES,
                        PARSE_JSON(AFFECTED_PACKAGES_JSON) AS AFFECTED_PACKAGES,
                        TRY_TO_TIMESTAMP_TZ(PUBLISHED_AT)  AS PUBLISHED_AT,
                        TRY_TO_TIMESTAMP_TZ(UPDATED_AT)    AS UPDATED_AT,
                        TRY_TO_TIMESTAMP_TZ(WITHDRAWN_AT)  AS WITHDRAWN_AT,
                        HTML_URL,
                        CREDITS_COUNT,
                        SOURCE_API,
                        TRY_TO_TIMESTAMP_TZ(INGESTED_AT)   AS INGESTED_AT,
                        PARSE_JSON(RAW_JSON_STR)           AS RAW_JSON
                    FROM TMP_GITHUB_RAW_STAGE
                ) AS src ON tgt.GHSA_ID = src.GHSA_ID
                WHEN MATCHED THEN UPDATE SET
                    CVE_ID             = src.CVE_ID,
                    SUMMARY            = src.SUMMARY,
                    DESCRIPTION        = src.DESCRIPTION,
                    SEVERITY           = src.SEVERITY,
                    CVSS_SCORE         = src.CVSS_SCORE,
                    CVSS_VECTOR_STRING = src.CVSS_VECTOR_STRING,
                    CWES               = src.CWES,
                    AFFECTED_PACKAGES  = src.AFFECTED_PACKAGES,
                    PUBLISHED_AT       = src.PUBLISHED_AT,
                    UPDATED_AT         = src.UPDATED_AT,
                    WITHDRAWN_AT       = src.WITHDRAWN_AT,
                    HTML_URL           = src.HTML_URL,
                    CREDITS_COUNT      = src.CREDITS_COUNT,
                    SOURCE_API         = src.SOURCE_API,
                    INGESTED_AT        = src.INGESTED_AT,
                    RAW_JSON           = src.RAW_JSON
                WHEN NOT MATCHED THEN INSERT (
                    GHSA_ID, CVE_ID, SUMMARY, DESCRIPTION, SEVERITY,
                    CVSS_SCORE, CVSS_VECTOR_STRING, CWES, AFFECTED_PACKAGES,
                    PUBLISHED_AT, UPDATED_AT, WITHDRAWN_AT, HTML_URL,
                    CREDITS_COUNT, SOURCE_API, INGESTED_AT, RAW_JSON
                ) VALUES (
                    src.GHSA_ID, src.CVE_ID, src.SUMMARY, src.DESCRIPTION,
                    src.SEVERITY, src.CVSS_SCORE, src.CVSS_VECTOR_STRING,
                    src.CWES, src.AFFECTED_PACKAGES, src.PUBLISHED_AT,
                    src.UPDATED_AT, src.WITHDRAWN_AT, src.HTML_URL,
                    src.CREDITS_COUNT, src.SOURCE_API, src.INGESTED_AT,
                    src.RAW_JSON
                )
            """)

        logger.info("Merged %d records into RAW.RAW_GITHUB_ADVISORIES", len(records))
        return len(records)

    def upsert_nvd_cves(self, records: list[dict]) -> int:
        return self._stage_and_merge(
            records,
            stage_table="NVD_CVES_STAGE",
            target_table="NVD_CVES_RAW",
            id_col="CVE_ID",
            id_func=lambda r: r.get("id", "UNKNOWN"),
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "SnowflakeLoader":
        return self

    def __exit__(self, *_) -> None:
        self.close()
