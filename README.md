# Snowflake Security Watchdog

A Cloud Security Intelligence Platform that ingests vulnerability data from public advisory feeds, lands it in Snowflake, transforms it through dbt layers, and surfaces anomalies, threat briefs, and infrastructure drift — all in one automated pipeline.

---

## What problem does it solve?

Security teams typically track CVEs and advisories manually, and infrastructure drift goes undetected until something breaks. This platform automates the full cycle: pull live vulnerability data from GitHub and NIST, score and classify it inside Snowflake, detect statistical anomalies with Snowpark, generate a weekly threat brief with Claude AI, and flag Terraform drift — all from a single CLI command.

---

## Security controls implemented

- **Statistical anomaly detection** — Snowpark computes per-category z-scores over `MART_VULNERABILITY_SUMMARY`; any row where `|z_score| > 2` is written to `SECURITY.VULNERABILITY_ANOMALIES`
- **Composite risk scoring** — `composite_risk_score = cvss_score × age_risk_multiplier` (1.0–2.0 based on how long a vuln has been unpatched), surfacing chronic high-CVSS issues that point-in-time snapshots miss
- **Age bucketing** — vulnerabilities are classified as `new / recent / aging / chronic` to prioritize remediation beyond raw CVSS
- **Infrastructure drift detection** — `terraform plan -detailed-exitcode` runs as a pipeline step; exit code 2 (drift detected) is recorded to `SECURITY.INFRASTRUCTURE_DRIFT`
- **SCD Type 2 snapshots** — `snap_ecosystem_risk` and `snap_pipeline_health` maintain full history with `dbt_valid_from` / `dbt_valid_to`, creating an audit trail of how risk posture changed over time
- **Enforced dbt contract** on `mart_critical_vulnerabilities` — column names and data types are locked; breaking changes fail the build
- **Pipeline health monitoring** — `mart_pipeline_health` tracks ingestion freshness and row counts per source, with `healthy / stale / empty` status

---

## What I learned

**The scale of today's security problem**

The security landscape is staggering in its size. NIST's NVD alone tracks over 250,000 published CVEs, with thousands added every month across every major language ecosystem. GitHub's Advisory Database adds another layer — ecosystem-specific vulnerabilities in pip, npm, Go, and Maven that never make it onto a security team's radar until something is actively exploited. No human team can monitor this volume manually. The only viable response is automated ingestion, classification, and prioritization — which is exactly what this platform does.

**dbt as a seamless transformation layer for security data**

dbt proved to be far more than an ETL tool. It enforces a clean separation between raw API responses (immutable, stored as Snowflake VARIANT), typed staging views, enrichment logic in intermediate models, and aggregated marts consumed downstream. The `contract.enforced: true` setting on `mart_critical_vulnerabilities` locks column names and types at build time — a breaking schema change fails the pipeline before it reaches production. The layered RAW → STAGING → INTERMEDIATE → MARTS pattern means every transformation is testable, documented, and replayable from source, which matters deeply for security data where audit traceability is not optional.

**Snowpark: Python intelligence running inside the warehouse**

Snowpark changed how I think about where computation belongs. Instead of pulling data out of Snowflake into a local Python process for anomaly detection, Snowpark runs the z-score window functions directly inside the warehouse — the data never leaves. This is the right model for security analytics: keep sensitive vulnerability data in the governed environment and push the computation to it, not the other way around. Writing Python DataFrame logic that compiles to Snowflake SQL also made the anomaly detection portable and testable without a live cluster.

**NIST NVD and GitHub APIs: external security validation**

Working with the NVD REST API v2.0 and GitHub's Advisory GraphQL API taught me that external security intelligence is only as good as your ingestion discipline. The NVD enforces rate limits (0.6 s per request with an API key, 6 s without) and uses a specific date format (`YYYY-MM-DDTHH:MM:SS.000+00:00`) that breaks silently if wrong. GitHub's cursor-based GraphQL pagination requires tracking continuation tokens across pages. Both APIs update existing records in place, which means an append-only load strategy will silently miss corrections — the MERGE-based upsert pattern (bulk load into a temp table, then MERGE on primary ID) ensures the warehouse always reflects the latest advisory state. External feeds like these represent the world's collective knowledge of known vulnerabilities; getting the ingestion right is the foundation everything else depends on.

**Internal vs external security validation**

This project made the distinction between internal and external security validation concrete. External validation — pulling from NIST NVD and GitHub Advisories — tells you what the world knows is vulnerable. Internal validation — Snowpark anomaly detection, pipeline health monitoring, SCD Type 2 snapshots, and enforced dbt contracts — tells you whether your own data, pipelines, and infrastructure are behaving as expected. Both are necessary. A platform that only watches external feeds will miss the anomaly in its own data. A platform that only monitors itself will miss the CVE that was quietly published last week affecting a dependency it runs on. The combination is what makes this a real security intelligence platform rather than just a dashboard.

**Terraform and infrastructure drift**

Terraform drift is one of the most underappreciated risks in cloud security. Infrastructure declared in code and infrastructure actually running in the cloud diverge constantly — through manual console changes, emergency hotfixes, or partial applies. Running `terraform plan -detailed-exitcode` as a pipeline step means drift is detected on every ingestion run, not just when an engineer happens to remember. Exit code 2 means Terraform found differences between declared and actual state; that result is written to `SECURITY.INFRASTRUCTURE_DRIFT` with a timestamp, creating a persistent record of when drift appeared and how long it persisted. The lesson: infrastructure state validation belongs in the data pipeline, not in a separate manual process that nobody runs consistently.

---

## Tools used

| Layer | Tool |
|---|---|
| Data sources | GitHub Advisory GraphQL API, NIST NVD REST API v2.0 |
| Ingestion | Python (`requests`, `snowflake-connector-python`, `snowflake-snowpark-python`) |
| Warehouse | Snowflake (ANALYTICS database, key-pair auth) |
| Transformation | dbt Core (RAW → STAGING → INTERMEDIATE → MARTS) |
| Anomaly detection | Snowpark (Python, window functions, z-scores) |
| Threat brief | Claude AI (`anthropic` SDK) |
| Infrastructure | Terraform (Snowflake provider) |
| Env management | `python-dotenv`, PKCS8 private key |

