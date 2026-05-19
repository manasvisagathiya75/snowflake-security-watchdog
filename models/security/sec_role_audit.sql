{{ config(materialized='view', schema='security') }}

WITH role_grants AS (
    SELECT
        grantee_name,
        role AS granted_role,
        granted_by,
        created_on
    FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
),

user_last_login AS (
    SELECT
        user_name,
        MAX(event_timestamp) AS last_login
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE is_success = 'YES'
    GROUP BY user_name
),

audit AS (
    SELECT
        r.grantee_name AS user_name,
        r.granted_role,
        u.last_login,
        DATEDIFF(day, u.last_login, CURRENT_TIMESTAMP) AS days_since_login,
        CASE
            WHEN r.granted_role IN ('SYSADMIN','ACCOUNTADMIN')
              AND DATEDIFF(day, u.last_login, CURRENT_TIMESTAMP) > 30
                THEN 'admin_role_unused_30_days'
            WHEN DATEDIFF(day, u.last_login, CURRENT_TIMESTAMP) > 90
                THEN 'user_inactive_90_days'
            WHEN r.granted_role = 'ACCOUNTADMIN'
                THEN 'accountadmin_flag_review'
            ELSE NULL
        END AS risk_flag
    FROM role_grants r
    LEFT JOIN user_last_login u
        ON r.grantee_name = u.user_name
)

SELECT * FROM audit
WHERE risk_flag IS NOT NULL