{{ config(materialized='table', schema='security') }}

WITH anomaly_count AS (
    SELECT COUNT(*) AS total_anomalies
    FROM {{ ref('sec_anomalous_queries') }}
),

role_risk_count AS (
    SELECT COUNT(*) AS total_role_risks
    FROM {{ ref('sec_role_audit') }}
),

pii_exposed_count AS (
    SELECT COUNT(*) AS total_exposed_columns
    FROM {{ ref('sec_pii_exposure') }}
    WHERE exposure_status = 'EXPOSED - ACTION REQUIRED'
),

pii_protected_count AS (
    SELECT COUNT(*) AS total_protected_columns
    FROM {{ ref('sec_pii_exposure') }}
    WHERE exposure_status = 'PROTECTED'
)

SELECT
    CURRENT_TIMESTAMP AS report_generated_at,
    a.total_anomalies,
    r.total_role_risks,
    p.total_exposed_columns,
    pr.total_protected_columns,
    CASE
        WHEN a.total_anomalies = 0
         AND r.total_role_risks = 0
         AND p.total_exposed_columns = 0
            THEN 'GREEN - No issues detected'
        WHEN p.total_exposed_columns > 0
          OR r.total_role_risks > 0
            THEN 'AMBER - Issues require attention'
        ELSE 'RED - Immediate action required'
    END  AS security_health_status
FROM anomaly_count a
CROSS JOIN role_risk_count r
CROSS JOIN pii_exposed_count p
CROSS JOIN pii_protected_count pr