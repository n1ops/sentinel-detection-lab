resource "azurerm_sentinel_automation_rule" "auto_assign_high_severity" {
  name                       = "56094f72-ac3f-40e7-a0c0-47bd95f70336"
  display_name               = "Auto-assign high severity incidents to SOC queue"
  log_analytics_workspace_id = var.workspace_id
  order                      = 1
  enabled                    = true

  condition_json = jsonencode([{
    conditionProperties = {
      operator       = "Equals"
      propertyName   = "IncidentSeverity"
      propertyValues = ["High"]
    }
    conditionType = "Property"
  }])

  action_incident {
    order  = 1
    status = "Active"
  }
}

resource "azurerm_sentinel_automation_rule" "auto_tag_phishing" {
  name                       = "7a1c3e8b-d5f2-4a96-b3e1-9c8d2f4a6b70"
  display_name               = "Auto-tag phishing-related incidents"
  log_analytics_workspace_id = var.workspace_id
  order                      = 2
  enabled                    = true

  condition_json = jsonencode([{
    conditionProperties = {
      operator       = "Contains"
      propertyName   = "IncidentLabel"
      propertyValues = ["T1566"]
    }
    conditionType = "Property"
  }])

  action_incident {
    order  = 1
    labels = ["Phishing", "InitialAccess"]
  }
}

resource "azurerm_sentinel_automation_rule" "auto_close_informational" {
  name                       = "c2d4e6f8-a1b3-5c7d-9e0f-2a4b6c8d0e1f"
  display_name               = "Auto-close informational incidents after enrichment"
  log_analytics_workspace_id = var.workspace_id
  order                      = 3
  enabled                    = true

  condition_json = jsonencode([{
    conditionProperties = {
      operator       = "Equals"
      propertyName   = "IncidentSeverity"
      propertyValues = ["Informational"]
    }
    conditionType = "Property"
  }])

  action_incident {
    order                  = 1
    status                 = "Closed"
    classification         = "Undetermined"
    classification_comment = "Auto-closed: Informational severity incident resolved by automation"
  }
}
