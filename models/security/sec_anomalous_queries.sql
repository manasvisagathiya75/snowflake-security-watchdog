{{ config(
    materialized='view',
    schema='security'
) }}

WITH query_log AS (
    SELECT
        query_id,
        user_name,
        role_name,
        query_text,
        bytes_scanned,
        rows_produced,
        start_time,
        execution_status
    FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE start_time >= DATEADD(day, -7, CURRENT_TIMESTAMP)
),

flagged AS (
    SELECT *,
        CASE
            WHEN bytes_scanned > 5368709120
                THEN 'large_scan_over_5gb'
            WHEN HOUR(start_time) NOT BETWEEN 6 AND 22
                THEN 'off_hours_access'
            WHEN LOWER(query_text) ILIKE '%password%'
              OR LOWER(query_text) ILIKE '%secret%'
              OR LOWER(query_text) ILIKE '%ssn%'
                THEN 'sensitive_column_access'
            WHEN rows_produced > 1000000
                THEN 'large_export'
            ELSE NULL
        END AS flag_reason
    FROM query_log
)

SELECT * FROM flagged
WHERE flag_reason IS NOT NULL
ORDER BY start_time DESC