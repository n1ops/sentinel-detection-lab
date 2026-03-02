terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "sentinel" {
  name     = "${var.resource_prefix}-sentinel-lab"
  location = var.location

  tags = {
    Environment = "Lab"
    Project     = "Sentinel Detection Lab"
    ManagedBy   = "Terraform"
  }
}
