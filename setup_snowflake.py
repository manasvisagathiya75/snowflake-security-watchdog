import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
)
import snowflake.connector

load_dotenv()

key_path = os.getenv("SNOWFLAKE_PRIVATE_KEY_PATH")
passphrase_raw = os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE") or ""
passphrase = passphrase_raw.encode() if passphrase_raw else None

with open(key_path, "rb") as f:
    private_key = load_pem_private_key(f.read(), password=passphrase)

private_key_der = private_key.private_bytes(
    encoding=Encoding.DER,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption(),
)

conn = snowflake.connector.connect(
    account=os.getenv("SNOWFLAKE_ACCOUNT"),
    user=os.getenv("SNOWFLAKE_USER"),
    private_key=private_key_der,
    database=os.getenv("SNOWFLAKE_DATABASE"),
    warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
    role="ACCOUNTADMIN",  # schema/table creation requires ACCOUNTADMIN on this account
)

statements = [
    ("ANALYTICS.RAW",          "CREATE SCHEMA IF NOT EXISTS ANALYTICS.RAW"),
    ("ANALYTICS.STAGING",      "CREATE SCHEMA IF NOT EXISTS ANALYTICS.STAGING"),
    ("ANALYTICS.INTERMEDIATE", "CREATE SCHEMA IF NOT EXISTS ANALYTICS.INTERMEDIATE"),
    ("ANALYTICS.MARTS",        "CREATE SCHEMA IF NOT EXISTS ANALYTICS.MARTS"),
    ("ANALYTICS.RAW.RAW_GITHUB_ADVISORIES", """
        CREATE TABLE IF NOT EXISTS ANALYTICS.RAW.RAW_GITHUB_ADVISORIES (
            GHSA_ID               VARCHAR(50),
            CVE_ID                VARCHAR(30),
            SUMMARY               VARCHAR(2000),
            DESCRIPTION           TEXT,
            SEVERITY              VARCHAR(20),
            CVSS_SCORE            FLOAT,
            CVSS_VECTOR_STRING    VARCHAR(200),
            CWES                  VARIANT,
            AFFECTED_PACKAGES     VARIANT,
            PUBLISHED_AT          TIMESTAMP_TZ,
            UPDATED_AT            TIMESTAMP_TZ,
            WITHDRAWN_AT          TIMESTAMP_TZ,
            HTML_URL              VARCHAR(500),
            CREDITS_COUNT         INTEGER,
            SOURCE_API            VARCHAR(50),
            INGESTED_AT           TIMESTAMP_TZ,
            RAW_JSON              VARIANT
        )
    """),
    ("ANALYTICS.RAW.RAW_NVD_CVES", """
        CREATE TABLE IF NOT EXISTS ANALYTICS.RAW.RAW_NVD_CVES (
            CVE_ID                VARCHAR(30),
            SOURCE_IDENTIFIER     VARCHAR(200),
            PUBLISHED_AT          TIMESTAMP_TZ,
            LAST_MODIFIED_AT      TIMESTAMP_TZ,
            VULN_STATUS           VARCHAR(50),
            DESCRIPTION           TEXT,
            CVSS_V3_SCORE         FLOAT,
            CVSS_V3_VECTOR        VARCHAR(200),
            CVSS_V3_SEVERITY      VARCHAR(20),
            WEAKNESSES            VARIANT,
            AFFECTED_CONFIGS      VARIANT,
            REFERENCES            VARIANT,
            INGESTED_AT           TIMESTAMP_TZ,
            RAW_JSON              VARIANT
        )
    """),
]

cur = conn.cursor()
for name, sql in statements:
    cur.execute(sql)
    print(f"Created: {name}")

cur.close()
conn.close()
