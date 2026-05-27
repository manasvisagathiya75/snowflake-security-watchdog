output "warehouse_name" {
  description = "Name of the provisioned Snowflake warehouse."
  value       = snowflake_warehouse.project2_wh.name
}

output "database_name" {
  description = "Name of the provisioned Snowflake database."
  value       = snowflake_database.analytics.name
}

output "reader_role_name" {
  description = "Name of the read-only role for the marts layer."
  value       = snowflake_account_role.project2_read_role.name
}

output "writer_role_name" {
  description = "Name of the write role for the ingestion pipeline."
  value       = snowflake_account_role.project2_write_role.name
}
