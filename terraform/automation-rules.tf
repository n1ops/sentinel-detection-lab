resource "azurerm_sentinel_automation_rule" "auto_assign_high_severity" {
  name                       = "auto-assign-high-severity"
  display_name               = "Auto-assign high severity incidents to SOC queue"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  order                      = 1
  enabled                    = true

  condition_json = jsonencode({
    clauses = [{
      conditionProperties = {
        operator = "Equals"
        propertyName = "IncidentSeverity"
        propertyValues = ["High"]
      }
      conditionType = "Property"
    }]
  })

  action_incident {
    order  = 1
    status = "Active"
  }
}

resource "azurerm_sentinel_automation_rule" "auto_tag_phishing" {
  name                       = "auto-tag-phishing"
  display_name               = "Auto-tag phishing-related incidents"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  order                      = 2
  enabled                    = true

  condition_json = jsonencode({
    clauses = [{
      conditionProperties = {
        operator = "Contains"
        propertyName = "IncidentLabel"
        propertyValues = ["T1566"]
      }
      conditionType = "Property"
    }]
  })

  action_incident {
    order  = 1
    labels = ["Phishing", "InitialAccess"]
  }
}

resource "azurerm_sentinel_automation_rule" "auto_close_informational" {
  name                       = "auto-close-informational"
  display_name               = "Auto-close informational incidents after enrichment"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  order                      = 3
  enabled                    = true

  condition_json = jsonencode({
    clauses = [{
      conditionProperties = {
        operator = "Equals"
        propertyName = "IncidentSeverity"
        propertyValues = ["Informational"]
      }
      conditionType = "Property"
    }]
  })

  action_incident {
    order                  = 1
    status                 = "Closed"
    classification         = "BenignPositive"
    classification_comment = "Auto-closed: Informational severity incident resolved by automation"
  }
}
