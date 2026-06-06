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

`run_ingestion.py` is the CLI entry point. It runs five sequential steps: ingest raw data → Snowpark anomaly detection → threat brief generation → Terraform drift detection.

```powershell
# Full load (all 5 steps)
python run_ingestion.py --source all

# Incremental load (records updated since a date)
python run_ingestion.py --source all --since 2024-01-01

# Single source only
python run_ingestion.py --source github
python run_ingestion.py --source nvd

# Skip optional steps
python run_ingestion.py --skip-brief        # skip threat brief generation
python run_ingestion.py --skip-drift        # skip Terraform drift detection
```

Each ingestion module can also be run standalone:
```powershell
python -m ingestion.anomaly_detection
python -m ingestion.threat_summarizer      # saves report to reports/threat_brief_YYYY-MM-DD.txt
python -m ingestion.drift_detector
```

## dbt Commands

```bash
cd dbt/
dbt deps                                    # Install packages from packages.yml
dbt run                                     # Run all models
dbt run -s staging                          # Run only the staging layer
dbt run -s +mart_critical_vulnerabilities   # Run a mart and all upstream deps
dbt test                                    # Run all schema/data tests
dbt build -s staging                        # run + test a layer atomically
dbt source freshness                        # Check RAW source table freshness
dbt snapshot                                # Run snap_ecosystem_risk and snap_pipeline_health
```

## Architecture

### Data Flow & Pipeline Steps

```
GitHub Advisory GraphQL API ─┐
                              ├─► ingestion/ ─► ANALYTICS.RAW ─► dbt ─► MARTS
NIST NVD REST API v2.0 ───────┘                                     │
                                                                     ▼
                                          ANALYTICS.SECURITY (anomalies, threat briefs, drift)
```

### Snowflake Schemas (ANALYTICS database, account: RK18195.us-east-2.aws)

| Schema | Purpose |
|---|---|
| `RAW` | Full API responses stored as VARIANT. Tables: `GITHUB_ADVISORIES_RAW`, `NVD_CVES_RAW`. Never modified after load. |
| `STAGING` | dbt views that parse VARIANT columns into typed fields, 1:1 with RAW tables. |
| `INTERMEDIATE` | dbt tables joining/enriching across staging sources. |
| `MARTS` | Final aggregated dbt tables consumed by dashboards and downstream Python. |
| `SECURITY` | Python-managed tables: `VULNERABILITY_ANOMALIES`, `THREAT_BRIEFS`, `INFRASTRUCTURE_DRIFT`. Also holds dbt snapshot history via `SNAP_ECOSYSTEM_RISK` and `SNAP_PIPELINE_HEALTH`. |

### Ingestion Layer (`ingestion/`)

- **`github_advisories.py`** — `GitHubAdvisoryFetcher`: cursor-based GraphQL pagination. Fetches ecosystems `[pip, npm, go, maven]` at `critical/high` severity, max 2 pages per call. Supports incremental loads via `updatedSince`.
- **`nvd_cves.py`** — `NVDFetcher`: index-based pagination of NVD API v2.0 with automatic rate-limit handling (0.6 s delay with API key, 6 s without). Supports `lastModStartDate`/`lastModEndDate` for incremental loads.
- **`load_to_snowflake.py`** — `SnowflakeLoader`: key-pair auth, creates RAW tables on first run, upserts via write_pandas staging-table MERGE pattern.
- **`anomaly_detection.py`** — Snowpark session against `MART_VULNERABILITY_SUMMARY`; computes per-category z-scores using window functions; writes rows where `|z_score| > 2` to `SECURITY.VULNERABILITY_ANOMALIES`.
- **`threat_summarizer.py`** — Queries multiple MART tables, renders a formatted weekly threat brief to stdout, persists to `SECURITY.THREAT_BRIEFS` in Snowflake and to `reports/threat_brief_YYYY-MM-DD.txt` on disk.
- **`drift_detector.py`** — Runs `terraform plan -detailed-exitcode`; parses exit code (0 = clean, 2 = drift, 1 = error); writes results to `SECURITY.INFRASTRUCTURE_DRIFT`. Sets env vars from `.env` as `TF_VAR_*` and strips conflicting Snowflake provider env vars before invoking Terraform.

### dbt Models

**Staging** (views in `STAGING` schema):
- `stg_github_advisories` — parses VARIANT from `GITHUB_ADVISORIES_RAW`, typed fields

**Intermediate** (tables in `INTERMEDIATE` schema):
- `int_vulnerabilities_enriched` — adds `age_bucket` (new/recent/aging/chronic based on days since published), `age_risk_multiplier` (1.0–2.0), `vulnerability_category` (keyword-matched from summary), and `composite_risk_score = cvss_score * age_risk_multiplier`

**Marts** (tables in `MARTS` schema):
- `mart_critical_vulnerabilities` — rows from intermediate where `composite_risk_score >= 9.0`; has an enforced contract (`contract.enforced: true`)
- `mart_ecosystem_risk` — per-ecosystem aggregation of vulnerability counts and risk scores
- `mart_vulnerability_summary` — cross-tabulation by severity + age_bucket + vulnerability_category
- `mart_pipeline_health` — ingestion freshness and row-count health check (in `monitoring/` folder, but materializes to MARTS schema)

**Snapshots** (SCD Type 2 history, stored in `SECURITY` schema):
- `snap_ecosystem_risk` — tracks changes to ecosystem risk metrics over time
- `snap_pipeline_health` — tracks pipeline health state changes over time

**Macros**:
- `generate_schema_name.sql` — overrides dbt's default schema naming to use the configured schema directly (no `<target>_` prefix)

### Key Implementation Patterns

- **Snowflake auth**: the private key PEM is read from disk, decoded to DER bytes with `cryptography`, and passed directly as `private_key=` to `snowflake.connector.connect()`. Snowpark sessions use the same DER approach via `Session.builder.configs()`.
- **Upsert pattern**: records are bulk-loaded into a `CREATE OR REPLACE TEMPORARY TABLE` via `write_pandas`, then merged into the target with a single `MERGE` statement keyed on the record's primary ID.
- **Incremental field**: every yielded record gets `_fetched_at` (ISO 8601 UTC) appended by the fetcher before being passed to the loader.
- **NVD date format**: the API expects `YYYY-MM-DDTHH:MM:SS.000+00:00`.
- **SECURITY schema tables**: created lazily by Python on first run (`CREATE TABLE IF NOT EXISTS`), not managed by Terraform or dbt.

### Required Environment Variables (`.env`)

| Variable | Purpose |
|---|---|
| `SNOWFLAKE_ACCOUNT` | Account locator (e.g., `RK18195.us-east-2.aws`) |
| `SNOWFLAKE_USER` | Snowflake username |
| `SNOWFLAKE_PRIVATE_KEY_PATH` | Path to PKCS8 private key `.p8` file |
| `SNOWFLAKE_WAREHOUSE` | Warehouse name |
| `GITHUB_TOKEN` | PAT with `read:security_events` scope |
| `NVD_API_KEY` | Optional; enables higher NVD rate limits |
| `SNOWFLAKE_ROLE` | Optional; defaults to `ACCOUNTADMIN` if unset |
