variable "snowflake_account" {
  description = "Snowflake account identifier (e.g. RK18195.us-east-2.aws). Set via TF_VAR_snowflake_account or SNOWFLAKE_ACCOUNT."
  type        = string
}

variable "snowflake_user" {
  description = "Snowflake user login name. Maps to the `user` attribute in the snowflakedb/snowflake provider block."
  type        = string
}

variable "snowflake_role" {
  description = "Snowflake role used by Terraform. Must have CREATE DATABASE / WAREHOUSE / SCHEMA / ROLE privileges."
  type        = string
  default     = "ACCOUNTADMIN"
}

variable "snowflake_warehouse_size" {
  description = "Size of the project warehouse (x-small, small, medium, large, …)."
  type        = string
  default     = "x-small"
}

variable "project_name" {
  description = "Human-readable project name used in resource comments."
  type        = string
  default     = "cloud-security-intelligence"
}

variable "snowflake_private_key_path" {
  description = "Path to Snowflake private key PEM file"
  type        = string
}
