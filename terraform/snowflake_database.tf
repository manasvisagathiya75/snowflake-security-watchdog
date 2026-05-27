resource "snowflake_database" "analytics" {
  name    = "ANALYTICS"
  comment = "Main analytics database for security platform"
}
