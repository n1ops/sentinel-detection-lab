variable "location" {
  description = "Azure region for all resources"
  type        = string

  validation {
    condition     = can(regex("^[a-z]+[a-z0-9]*$", var.location))
    error_message = "Location must be a valid Azure region name (lowercase, no spaces)."
  }
}

variable "resource_prefix" {
  description = "Prefix for all resource names"
  type        = string

  validation {
    condition     = length(var.resource_prefix) >= 2 && length(var.resource_prefix) <= 10 && can(regex("^[a-z][a-z0-9-]*$", var.resource_prefix))
    error_message = "Resource prefix must be 2-10 characters, start with a letter, and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "log_retention_days" {
  description = "Log Analytics workspace retention in days (31 = free tier)"
  type        = number

  validation {
    condition     = var.log_retention_days >= 31 && var.log_retention_days <= 730
    error_message = "Retention must be between 31 (free tier) and 730 days."
  }
}
