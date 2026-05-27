{% snapshot snap_ecosystem_risk %}

  {{
    config(
      target_schema='SECURITY',
      unique_key='ecosystem_name',
      strategy='check',
      check_cols=[
        'total_vulnerabilities',
        'critical_count',
        'avg_risk_score',
        'max_risk_score'
      ]
    )
  }}

  SELECT
    ecosystem_name,
    total_vulnerabilities,
    critical_count,
    high_count,
    avg_risk_score,
    max_risk_score,
    current_timestamp() AS snapshotted_at

  FROM {{ ref('mart_ecosystem_risk') }}

{% endsnapshot %}
