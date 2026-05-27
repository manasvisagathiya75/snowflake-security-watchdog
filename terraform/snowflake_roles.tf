resource "snowflake_account_role" "project2_read_role" {
  name    = "PROJECT2_READER"
  comment = "Read-only access to marts layer"
}

resource "snowflake_account_role" "project2_write_role" {
  name    = "PROJECT2_WRITER"
  comment = "Write access for ingestion pipeline"
}

resource "snowflake_grant_privileges_to_account_role" "reader_select_marts" {
  account_role_name = snowflake_account_role.project2_read_role.name
  privileges        = ["SELECT"]

  on_schema_object {
    all {
      object_type_plural = "TABLES"
      in_schema          = "\"ANALYTICS\".\"MARTS\""
    }
  }

  depends_on = [
    snowflake_schema.analytics_marts,
  ]
}

resource "snowflake_grant_privileges_to_account_role" "writer_insert_update_raw" {
  account_role_name = snowflake_account_role.project2_write_role.name
  privileges        = ["INSERT", "UPDATE"]

  on_schema_object {
    all {
      object_type_plural = "TABLES"
      in_schema          = "\"ANALYTICS\".\"RAW\""
    }
  }

  depends_on = [
    snowflake_schema.analytics_raw,
  ]
}
