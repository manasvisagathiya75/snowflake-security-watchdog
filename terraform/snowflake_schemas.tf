resource "snowflake_schema" "analytics_raw" {
  database = snowflake_database.analytics.name
  name     = "RAW"
  comment  = "Landing zone for raw API responses. Full JSON payloads; never modified after load."
}

resource "snowflake_schema" "analytics_staging" {
  database = snowflake_database.analytics.name
  name     = "STAGING"
  comment  = "dbt staging layer: 1-to-1 views over RAW tables with typed columns and renamed fields."
}

resource "snowflake_schema" "analytics_intermediate" {
  database = snowflake_database.analytics.name
  name     = "INTERMEDIATE"
  comment  = "dbt intermediate layer: enriched and joined models that feed the marts layer."
}

resource "snowflake_schema" "analytics_marts" {
  database = snowflake_database.analytics.name
  name     = "MARTS"
  comment  = "dbt marts layer: final aggregations and views consumed by BI tools and dashboards."
}
