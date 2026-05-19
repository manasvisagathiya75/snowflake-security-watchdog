{{ config(materialized='view', schema='security') }}

WITH masked_columns AS (
    SELECT
        c.table_catalog     AS database_name,
        c.table_schema      AS schema_name,
        c.table_name,
        c.column_name,
        c.data_type,
        CASE
            WHEN LOWER(c.column_name) ILIKE '%email%'      THEN 'email - masked'
            WHEN LOWER(c.column_name) ILIKE '%phone%'      THEN 'phone - masked'
            WHEN LOWER(c.column_name) ILIKE '%ssn%'        THEN 'ssn - masked'
            WHEN LOWER(c.column_name) ILIKE '%address%'    THEN 'address - masked'
            WHEN LOWER(c.column_name) ILIKE '%password%'   THEN 'password - EXPOSED'
            WHEN LOWER(c.column_name) ILIKE '%secret%'     THEN 'secret - EXPOSED'
            WHEN LOWER(c.column_name) ILIKE '%credit_card%' THEN 'credit card - EXPOSED'
            WHEN LOWER(c.column_name) ILIKE '%dob%'        THEN 'date of birth - EXPOSED'
            WHEN LOWER(c.column_name) ILIKE '%birth%'      THEN 'date of birth - EXPOSED'
            ELSE NULL
        END AS pii_classification,
        CASE
            WHEN LOWER(c.column_name) ILIKE '%email%'      THEN 'PROTECTED'
            WHEN LOWER(c.column_name) ILIKE '%phone%'      THEN 'PROTECTED'
            WHEN LOWER(c.column_name) ILIKE '%ssn%'        THEN 'PROTECTED'
            WHEN LOWER(c.column_name) ILIKE '%address%'    THEN 'PROTECTED'
            WHEN LOWER(c.column_name) ILIKE '%password%'   THEN 'EXPOSED - ACTION REQUIRED'
            WHEN LOWER(c.column_name) ILIKE '%secret%'     THEN 'EXPOSED - ACTION REQUIRED'
            WHEN LOWER(c.column_name) ILIKE '%credit_card%' THEN 'EXPOSED - ACTION REQUIRED'
            WHEN LOWER(c.column_name) ILIKE '%dob%'        THEN 'EXPOSED - ACTION REQUIRED'
            WHEN LOWER(c.column_name) ILIKE '%birth%'      THEN 'EXPOSED - ACTION REQUIRED'
            ELSE NULL
        END AS exposure_status,
        CURRENT_TIMESTAMP AS checked_at
    FROM ANALYTICS.INFORMATION_SCHEMA.COLUMNS c
    WHERE c.table_schema != 'INFORMATION_SCHEMA'
)

SELECT * FROM masked_columns
WHERE pii_classification IS NOT NULL
ORDER BY exposure_status DESC, table_name, column_name