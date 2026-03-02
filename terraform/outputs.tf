output "resource_group_name" {
  description = "Name of the resource group"
  value       = module.workspace.resource_group_name
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace resource ID"
  value       = module.workspace.workspace_id
  sensitive   = true
}

output "log_analytics_workspace_name" {
  description = "Log Analytics workspace name"
  value       = module.workspace.workspace_name
}

output "sentinel_portal_url" {
  description = "Direct link to the Sentinel portal for this workspace"
  value       = module.workspace.sentinel_portal_url
  sensitive   = true
}
