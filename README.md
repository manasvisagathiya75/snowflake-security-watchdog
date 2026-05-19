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
data engineers already have.

---

## Threat model — what this detects

| Threat | Model | How |
|--------|-------|-----|
| Anomalous queries (large scans, off-hours access, sensitive column access) | `sec_anomalous_queries` | Queries ACCOUNT_USAGE.QUERY_HISTORY and flags suspicious patterns |
| Over-privileged users and inactive admin accounts | `sec_role_audit` | Audits GRANTS_TO_USERS against LOGIN_HISTORY |
| PII columns without masking policies | `sec_pii_exposure` | Scans INFORMATION_SCHEMA.COLUMNS for sensitive column names |

---

## Security controls implemented

- Column-level masking policies on email, phone, SSN, address
- Role-based data access (ACCOUNTADMIN sees real data, REPORTER sees masked data)
- Automated detection of suspicious query patterns
- Automated access control audit
- PII exposure tracker across entire warehouse

---

## Project structure
models/
security/
sec_anomalous_queries.sql  -- flags suspicious queries
sec_role_audit.sql         -- audits user permissions
sec_pii_exposure.sql       -- tracks PII column exposure
macros/
generate_schema_name.sql     -- schema routing macro

---
## How to deploy

**Requirements:** Snowflake account, dbt Core or dbt Cloud

**1. Clone the repo**
git clone https://github.com/yourusername/snowflake-security-watchdog

**2. Grant ACCOUNT_USAGE access**
```sql
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE TRANSFORMER;
```

**3. Run the models**
dbt run --select sec_anomalous_queries sec_role_audit sec_pii_exposure

---

## Security concepts covered

- Principle of least privilege
- Column-level security and data masking
- Anomaly detection using query history
- PII classification and exposure tracking
- SOC 2 access review requirements
- Role-based access control (RBAC)

---

## What I learned building this

- Snowflake's ACCOUNT_USAGE schema is a rich source of
  security telemetry that most data engineers never use
- Column masking policies enforce different data views per
  role with zero changes to query logic
- The same SQL and dbt skills used for analytics pipelines
  apply directly to security monitoring
- Access control auditing is a core SOC 2 requirement —
  this model automates what auditors check manually

---

## Tools used

- Snowflake (warehouse, ACCOUNT_USAGE, masking policies)
- dbt Cloud (transformation, testing, documentation)
- SQL (anomaly detection logic, access auditing)
