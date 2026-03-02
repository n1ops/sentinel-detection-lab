variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "resource_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "rg"
}

variable "log_retention_days" {
  description = "Log Analytics workspace retention in days (31 = free tier)"
  type        = number
  default     = 31

  validation {
    condition     = var.log_retention_days >= 31 && var.log_retention_days <= 730
    error_message = "Retention must be between 31 (free tier) and 730 days."
  }
}
