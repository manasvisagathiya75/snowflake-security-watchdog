# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cloud Security Intelligence Platform. Ingests vulnerability data from the GitHub Advisory GraphQL API and NIST NVD REST API v2.0, lands raw JSON into Snowflake, and transforms it through dbt layers (RAW → STAGING → INTERMEDIATE → MARTS). Snowflake infrastructure is managed with Terraform.

## Setup

```powershell
# Activate virtual environment (Windows)
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env   # then populate all values
```

Key-pair auth requires a private key registered with Snowflake:
```powershell
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out keys\snowflake_private_key.p8
openssl rsa -in keys\snowflake_private_key.p8 -pubout -out keys\snowflake_public_key.pub
# In Snowflake: ALTER USER <user> SET RSA_PUBLIC_KEY='<public key without headers/footers>';
```

## Running the Pipeline

```powershell
# Full load of all sources
python run_ingestion.py --source all

# Incremental load (records updated since a date)
python run_ingestion.py --source all --since 2024-01-01

# Single source
python run_ingestion.py --source github
python run_ingestion.py --source nvd
```

## dbt Commands

```bash
cd dbt/
dbt deps                                    # Install packages from packages.yml
dbt run                                     # Run all models
dbt run -s staging                          # Run only the staging layer
dbt run -s +marts.vulnerability_summary     # Run a mart and all its upstream deps
dbt test                                    # Run all schema/data tests
dbt build -s staging                        # run + test a layer atomically
dbt source freshness                        # Check RAW source table freshness
```

## Architecture

### Data Flow

```
GitHub Advisory GraphQL API ─┐
                              ├─► ingestion/ ─► ANALYTICS.RAW ─► dbt ─► MARTS
NIST NVD REST API v2.0 ───────┘
```

### Snowflake Schemas (ANALYTICS database, account: RK18195.us-east-2.aws)

| Schema | Purpose |
|---|---|
| `RAW` | Full API responses stored as VARIANT. Never modified after load. Tables: `GITHUB_ADVISORIES_RAW`, `NVD_CVES_RAW`. |
| `STAGING` | dbt models that parse VARIANT columns into typed fields, 1:1 with RAW tables. |
| `INTERMEDIATE` | dbt models joining/enriching across staging sources. |
| `SECURITY` | Domain-specific enrichment models. |
| `MARTS` | Final aggregations and views consumed by BI tools. |

### Ingestion Layer (`ingestion/`)

- **`github_advisories.py`** — `GitHubAdvisoryFetcher`: cursor-based GraphQL pagination of the GitHub Security Advisory API. Supports incremental loads via `updatedSince`.
- **`nvd_cves.py`** — `NVDFetcher`: index-based pagination of NVD API v2.0 with automatic rate-limit handling (0.6 s delay with API key, 6 s without). Supports `lastModStartDate`/`lastModEndDate` for incremental loads.
- **`load_to_snowflake.py`** — `SnowflakeLoader`: establishes key-pair auth, creates RAW tables on first run, and upserts using a write_pandas staging-table MERGE pattern to avoid row-by-row round trips.

`run_ingestion.py` is the CLI entry point.

### Key Implementation Patterns

- **Snowflake auth**: the private key PEM is read from disk, decoded to DER bytes with `cryptography`, and passed directly as `private_key=` to `snowflake.connector.connect()`.
- **Upsert pattern**: records are bulk-loaded into a `CREATE OR REPLACE TEMPORARY TABLE` via `write_pandas`, then merged into the target with a single `MERGE` statement. This keeps all raw JSON in the `RECORD VARIANT` column alongside a typed primary key.
- **Incremental field**: every yielded record gets `_fetched_at` (ISO 8601 UTC) appended by the fetcher before being passed to the loader.
- **NVD date format**: the API expects `YYYY-MM-DDTHH:MM:SS.000+00:00`.

### Planned dbt Structure (`dbt/`)

```
dbt/
├── dbt_project.yml
├── packages.yml
├── models/
│   ├── staging/          # stg_github_advisories.sql, stg_nvd_cves.sql
│   ├── intermediate/     # int_vulnerabilities_unified.sql
│   ├── security/         # domain enrichment models
│   └── marts/            # vulnerability_summary.sql, severity_trends.sql
├── tests/                # singular data tests
├── macros/
└── sources.yml           # freshness checks on RAW tables
```
