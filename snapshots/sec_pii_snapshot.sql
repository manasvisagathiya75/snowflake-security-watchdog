{% snapshot sec_pii_snapshot %}

{{
    config(
        target_schema='security',
        target_database='ANALYTICS',
        unique_key="column_name || '|' || table_name",
        strategy='check',
        check_cols=['exposure_status', 'pii_classification'],
        snowflake_warehouse='DEV_WH'
    )
}}

SELECT
    table_name,
    column_name,
    pii_classification,
    exposure_status,
    checked_at
FROM {{ ref('sec_pii_exposure') }}

{% endsnapshot %}