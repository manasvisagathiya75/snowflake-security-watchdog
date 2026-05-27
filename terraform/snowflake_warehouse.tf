resource "snowflake_warehouse" "project2_wh" {
  name           = "PROJECT2_WH"
  warehouse_size = var.snowflake_warehouse_size
  auto_suspend   = 60
  auto_resume    = true
  comment        = "Warehouse for Cloud Security Intelligence Platform"
}
