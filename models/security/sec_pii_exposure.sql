{{ config(
    materialized='view',
    schema='security',
    snowflake_warehouse='DEV_WH'
) }}

WITH masked_columns AS (
    SELECT
        c.table_catalog     AS database_name,
        c.table_schema      AS schema_name,
        c.table_name,
        c.column_name,
        c.data_type,
        {{ flag_sensitive_column('c.column_name') }} AS pii_classification,
        CASE
            WHEN {{ flag_sensitive_column('c.column_name') }} = 'NOT_SENSITIVE'
                THEN NULL
            WHEN LOWER(c.column_name) ILIKE '%email%'
              OR LOWER(c.column_name) ILIKE '%phone%'
              OR LOWER(c.column_name) ILIKE '%ssn%'
              OR LOWER(c.column_name) ILIKE '%address%'
                THEN 'PROTECTED'
            ELSE 'EXPOSED - ACTION REQUIRED'
        END AS exposure_status,
        CURRENT_TIMESTAMP AS checked_at
    FROM ANALYTICS.INFORMATION_SCHEMA.COLUMNS c
    WHERE c.table_schema != 'INFORMATION_SCHEMA'
)

SELECT * FROM masked_columns
WHERE pii_classification != 'NOT_SENSITIVE'
ORDER BY exposure_status DESC, table_name, column_name