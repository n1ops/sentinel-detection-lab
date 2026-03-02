output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.sentinel.name
}

output "workspace_id" {
  description = "Log Analytics workspace resource ID"
  value       = azurerm_log_analytics_workspace.sentinel.id
  sensitive   = true
}

output "workspace_name" {
  description = "Log Analytics workspace name"
  value       = azurerm_log_analytics_workspace.sentinel.name
}

output "onboarding_workspace_id" {
  description = "Sentinel onboarding workspace ID (used by rules and automation)"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
}

output "subscription_id" {
  description = "Current Azure subscription ID"
  value       = data.azurerm_subscription.current.id
}

output "sentinel_portal_url" {
  description = "Direct link to the Sentinel portal for this workspace"
  value       = "https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade/0/subscriptionId/${data.azurerm_subscription.current.subscription_id}/resourceGroup/${azurerm_resource_group.sentinel.name}/workspaceName/${azurerm_log_analytics_workspace.sentinel.name}"
  sensitive   = true
}
