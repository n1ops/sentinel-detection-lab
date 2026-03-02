# Note: Azure AD sign-in/audit log connector requires Azure AD P1/P2 license.
# Uncomment the block below if you have the appropriate licensing.
#
# resource "azurerm_sentinel_data_connector_azure_active_directory" "aad" {
#   name                       = "aad-connector"
#   log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
#   tenant_id                  = data.azurerm_subscription.current.tenant_id
# }

resource "azurerm_monitor_diagnostic_setting" "subscription_activity" {
  name                       = "sentinel-activity-logs"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel.id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "Alert"
  }

  enabled_log {
    category = "Policy"
  }
}
