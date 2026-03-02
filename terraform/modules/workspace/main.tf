data "azurerm_subscription" "current" {}

resource "azurerm_resource_group" "sentinel" {
  name     = "${var.resource_prefix}-sentinel-lab"
  location = var.location

  tags = {
    Environment = "Lab"
    Project     = "Sentinel Detection Lab"
    ManagedBy   = "Terraform"
  }
}

resource "azurerm_log_analytics_workspace" "sentinel" {
  name                       = "${var.resource_prefix}-sentinel-workspace"
  location                   = azurerm_resource_group.sentinel.location
  resource_group_name        = azurerm_resource_group.sentinel.name
  sku                        = "PerGB2018"
  retention_in_days          = var.log_retention_days
  internet_ingestion_enabled = false
  internet_query_enabled     = false

  tags = azurerm_resource_group.sentinel.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id                 = azurerm_log_analytics_workspace.sentinel.id
  customer_managed_key_enabled = false # TODO: Enable CMK encryption for production workloads

  lifecycle {
    prevent_destroy = true
  }
}
