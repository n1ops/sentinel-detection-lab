terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  # TODO: Uncomment and configure for remote state storage
  # backend "azurerm" {
  #   resource_group_name  = "tfstate-rg"
  #   storage_account_name = "yourstorageaccount"
  #   container_name       = "tfstate"
  #   key                  = "sentinel-lab.tfstate"
  #   use_oidc             = true
  # }

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.62.0"
    }
  }
}

provider "azurerm" {
  features {}
  resource_provider_registrations = "none"
}

# --- Module Calls ---

module "workspace" {
  source = "./modules/workspace"

  location           = var.location
  resource_prefix    = var.resource_prefix
  log_retention_days = var.log_retention_days
}

module "analytics_rules" {
  source = "./modules/analytics-rules"

  workspace_id    = module.workspace.onboarding_workspace_id
  detections_path = "${path.root}/../detections"
}

module "automation" {
  source = "./modules/automation"

  workspace_id = module.workspace.onboarding_workspace_id
}

module "connectors" {
  source = "./modules/connectors"

  workspace_id    = module.workspace.workspace_id
  subscription_id = module.workspace.subscription_id
}
