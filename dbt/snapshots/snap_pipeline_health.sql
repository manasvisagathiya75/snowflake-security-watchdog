{% snapshot snap_pipeline_health %}

  {{
    config(
      target_schema='SECURITY',
      unique_key='source_table',
      strategy='check',
      check_cols=[
        'pipeline_status',
        'total_rows',
        'hours_since_last_load'
      ]
    )
  }}

  SELECT
    source_table,
    pipeline_status,
    total_rows,
    rows_last_24h,
    rows_last_7d,
    hours_since_last_load,
    is_fresh,
    is_row_count_normal,
    last_ingested_at,
    current_timestamp() AS snapshotted_at

  FROM {{ ref('mart_pipeline_health') }}

{% endsnapshot %}
