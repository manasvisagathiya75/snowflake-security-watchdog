# Snowflake Security Watchdog

A DBT-native security monitoring layer that detects threats
and enforces data protection inside a Snowflake data warehouse.
Built to demonstrate the intersection of data engineering and
security engineering.

---

## What problem does this solve?

Most data teams focus on pipeline reliability and data quality
but ignore security. This project adds a security monitoring
layer directly inside dbt — using the same tools and skills
data engineers already have — without needing a separate
security tooling budget.

---

## Threat model — what this detects

| Threat | Model | How |
|--------|-------|-----|
| Anomalous queries — large scans, off-hours access, sensitive column queries | `sec_anomalous_queries` | Queries ACCOUNT_USAGE.QUERY_HISTORY and flags suspicious patterns |
| Over-privileged users and inactive admin accounts | `sec_role_audit` | Audits GRANTS_TO_USERS against LOGIN_HISTORY |
| PII columns without masking policies | `sec_pii_exposure` | Scans INFORMATION_SCHEMA.COLUMNS for sensitive column names |
| Historical PII exposure changes | `sec_pii_snapshot` | SCD Type 2 snapshot tracks every change to column exposure status |
| Overall security health | `sec_summary` | Aggregates all models into a single executive dashboard |


---

## Security controls implemented

- Column-level masking policies on email, phone, SSN,
  address, and date of birth
- Role-based data access — ACCOUNTADMIN sees real data,
  REPORTER sees masked data, same query same table
- Automated detection of suspicious query patterns
- Automated access control audit against login history
- PII exposure tracker across entire warehouse
- SCD Type 2 snapshot — full audit trail of every PII
  exposure change with timestamps
- source() references enabling full dbt lineage tracking

---

## Project structure
models/
security/
sec_anomalous_queries.sql  ← flags suspicious queries
sec_role_audit.sql         ← audits user permissions
sec_pii_exposure.sql       ← tracks PII column exposure
sec_summary.sql            ← executive security dashboard
schema.yml                 ← model descriptions
sources.yml                ← documented data sources
snapshots/
sec_pii_snapshot.sql         ← SCD Type 2 historical tracking
macros/
generate_schema_name.sql     ← schema routing macro
flag_sensitive_column.sql    ← reusable PII detection macro

---

## Snowflake schemas used

| Schema | Purpose |
|--------|---------|
| RAW | Raw source data with masking policies applied |
| STAGING | dbt staging models |
| SECURITY | All security monitoring models and snapshot |

---

## Roles and access control

| Role | Access |
|------|--------|
| ACCOUNTADMIN | Full access — sees real PII data |
| TRANSFORMER | Write access to all schemas — used by dbt |
| REPORTER | Read-only on MARTS — sees masked PII data |

---

## How to deploy

**Requirements:** Snowflake account, dbt Core or dbt Cloud

**2. Set up Snowflake — run in a worksheet as ACCOUNTADMIN**
```sql
CREATE WAREHOUSE IF NOT EXISTS DEV_WH
  WAREHOUSE_SIZE = 'X-SMALL'
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE;

CREATE DATABASE IF NOT EXISTS ANALYTICS;
CREATE SCHEMA IF NOT EXISTS ANALYTICS.RAW;
CREATE SCHEMA IF NOT EXISTS ANALYTICS.SECURITY;

CREATE ROLE IF NOT EXISTS TRANSFORMER;
GRANT USAGE ON WAREHOUSE DEV_WH TO ROLE TRANSFORMER;
GRANT ALL ON DATABASE ANALYTICS TO ROLE TRANSFORMER;
GRANT ALL ON ALL SCHEMAS IN DATABASE ANALYTICS TO ROLE TRANSFORMER;
GRANT ALL ON FUTURE TABLES IN DATABASE ANALYTICS TO ROLE TRANSFORMER;

GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE TRANSFORMER;
```

**3. Run the models**

dbt build
**4. Run the snapshot**
dbt snapshot


**5. Query the security dashboard**
```sql
SELECT * FROM ANALYTICS.SECURITY.SEC_SUMMARY;
```

---

## Key dbt concepts demonstrated

| Concept | Where used |
|---------|-----------|
| Sources with source() references | sec_anomalous_queries, sec_role_audit |
| Custom schema routing macro | macros/generate_schema_name.sql |
| Reusable macro | macros/flag_sensitive_column.sql |
| SCD Type 2 snapshot | snapshots/sec_pii_snapshot.sql |
| Model descriptions and documentation | schema.yml, sources.yml |
| Multi-model ref() dependencies | sec_summary refs all 3 models |
| View and table materializations | security views, summary table |
| Snowflake warehouse config per model | snowflake_warehouse in config block |

---

## Key Snowflake security concepts demonstrated

| Concept | Where used |
|---------|-----------|
| Column-level masking policies | ANALYTICS.RAW.CUSTOMERS |
| Role-based access control (RBAC) | TRANSFORMER, REPORTER roles |
| ACCOUNT_USAGE telemetry | Query history, login history, grants |
| Principle of least privilege | REPORTER read-only on MARTS only |
| PII classification | sec_pii_exposure model |
| Security audit trail | sec_pii_snapshot SCD Type 2 |

---

## Security concepts covered

- Principle of least privilege
- Column-level security and data masking
- Anomaly detection using query telemetry
- PII classification and exposure tracking
- SOC 2 access review requirements
- Role-based access control (RBAC)
- SCD Type 2 for security audit trails
- Data lineage for security traceability

---

## What I learned building this

- Snowflake's ACCOUNT_USAGE schema is a rich source of
  security telemetry that most data engineers never use
- Column masking policies enforce different data views per
  role with zero changes to consumer query logic
- The same SQL and dbt skills used for analytics pipelines
  apply directly to security monitoring
- Access control auditing (sec_role_audit) is a core SOC 2
  requirement — this model automates what auditors check manually
- SCD Type 2 snapshots turn a point-in-time security view
  into a full audit trail — critical for compliance
- source() references are not just best practice — they
  enable lineage, testing, and documentation that hardcoded
  table references cannot

---

## Tools used

- Snowflake — warehouse, ACCOUNT_USAGE telemetry,
  masking policies, RBAC
- dbt Cloud — transformation, snapshots, macros,
  documentation, lineage
- SQL — anomaly detection, access auditing, PII classification
- GitHub — version control and portfolio hosting
