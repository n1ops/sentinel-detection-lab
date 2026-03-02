locals {
  detection_files = {
    brute_force_signin = {
      file        = "${path.module}/../detections/credential-access/brute-force-signin.kql"
      name        = "Brute Force Sign-in Attempts"
      description = "Detects multiple failed sign-in attempts from a single IP within 1 hour"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["CredentialAccess"]
      techniques  = ["T1110.001"]
      entity_mappings = {
        ip      = { type = "IP", field = "IPAddress" }
        account = { type = "Account", field = "UserPrincipalName" }
      }
    }
    password_spray = {
      file        = "${path.module}/../detections/credential-access/password-spray.kql"
      name        = "Password Spray Attack"
      description = "Detects a single IP attempting sign-ins against multiple distinct accounts"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["CredentialAccess"]
      techniques  = ["T1110.003"]
      entity_mappings = {
        ip      = { type = "IP", field = "IPAddress" }
        account = { type = "Account", field = "TargetAccount" }
      }
    }
    impossible_travel = {
      file        = "${path.module}/../detections/credential-access/impossible-travel.kql"
      name        = "Impossible Travel Sign-in"
      description = "Detects a user signing in from geographically distant locations in a short time"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT24H"
      tactics     = ["CredentialAccess"]
      techniques  = ["T1078"]
      entity_mappings = {
        account = { type = "Account", field = "UserPrincipalName" }
        ip      = { type = "IP", field = "CurrentIPAddress" }
      }
    }
    phishing_inbox_rule = {
      file        = "${path.module}/../detections/initial-access/phishing-inbox-rule.kql"
      name        = "Suspicious Inbox Rule Created (Phishing Indicator)"
      description = "Detects creation of inbox rules that move or delete items post-compromise"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["InitialAccess"]
      techniques  = ["T1566.001"]
      entity_mappings = {
        account = { type = "Account", field = "UserId" }
      }
    }
    suspicious_oauth_consent = {
      file        = "${path.module}/../detections/initial-access/suspicious-oauth-consent.kql"
      name        = "Suspicious OAuth Application Consent"
      description = "Detects OAuth application consent grants with high-privilege permissions"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["InitialAccess"]
      techniques  = ["T1566.002"]
      entity_mappings = {
        account = { type = "Account", field = "InitiatedByUser" }
      }
    }
    new_inbox_forwarding_rule = {
      file        = "${path.module}/../detections/persistence/new-inbox-forwarding-rule.kql"
      name        = "New Inbox Forwarding Rule to External Domain"
      description = "Detects creation of email forwarding rules to external addresses"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["Persistence"]
      techniques  = ["T1137.005"]
      entity_mappings = {
        account = { type = "Account", field = "UserId" }
      }
    }
    suspicious_service_principal = {
      file        = "${path.module}/../detections/persistence/suspicious-service-principal.kql"
      name        = "Suspicious Service Principal Creation"
      description = "Detects creation of new service principals or app registrations"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["Persistence"]
      techniques  = ["T1136.003"]
      entity_mappings = {
        account = { type = "Account", field = "InitiatedByUser" }
      }
    }
    anomalous_rdp_signin = {
      file        = "${path.module}/../detections/lateral-movement/anomalous-rdp-signin.kql"
      name        = "Anomalous RDP Sign-in"
      description = "Detects RDP sign-ins from unusual source IPs or during off-hours"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["LateralMovement"]
      techniques  = ["T1021.001"]
      entity_mappings = {
        ip      = { type = "IP", field = "IPAddress" }
        account = { type = "Account", field = "UserPrincipalName" }
      }
    }
    multi_host_admin_logon = {
      file        = "${path.module}/../detections/lateral-movement/multi-host-admin-logon.kql"
      name        = "Multi-Host Admin Logon"
      description = "Detects a single account performing admin logons across multiple hosts"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["LateralMovement"]
      techniques  = ["T1078.002"]
      entity_mappings = {
        account = { type = "Account", field = "Account" }
        host    = { type = "Host", field = "SampleHost" }
      }
    }
    bulk_file_download = {
      file        = "${path.module}/../detections/exfiltration/bulk-file-download.kql"
      name        = "Bulk File Download from SharePoint/OneDrive"
      description = "Detects bulk file downloads from SharePoint or OneDrive"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["Exfiltration"]
      techniques  = ["T1567"]
      entity_mappings = {
        account = { type = "Account", field = "UserId" }
        ip      = { type = "IP", field = "ClientIP" }
      }
    }
    mail_forwarding_to_external = {
      file        = "${path.module}/../detections/exfiltration/mail-forwarding-to-external.kql"
      name        = "Mail Forwarding to External Domain"
      description = "Detects email auto-forwarding configured to external domains"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["Exfiltration"]
      techniques  = ["T1114.003"]
      entity_mappings = {
        account = { type = "Account", field = "UserId" }
      }
    }
    encoded_powershell = {
      file        = "${path.module}/../detections/defense-evasion/encoded-powershell.kql"
      name        = "Encoded PowerShell Execution"
      description = "Detects execution of encoded PowerShell commands"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["DefenseEvasion"]
      techniques  = ["T1027"]
      entity_mappings = {
        account = { type = "Account", field = "Account" }
        host    = { type = "Host", field = "Computer" }
      }
    }
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "detection" {
  for_each = local.detection_files

  name                       = each.key
  display_name               = each.value.name
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  description                = each.value.description
  severity                   = each.value.severity
  enabled                    = true
  query                      = file(each.value.file)
  query_frequency            = each.value.frequency
  query_period               = each.value.period
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = each.value.tactics
  techniques                 = each.value.techniques

  alert_details_override {
    description_format   = "{{message}}"
    display_name_format  = "${each.value.name} - {{UserPrincipalName}}"
  }

  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = [for k, v in each.value.entity_mappings : v.type]
    }
  }

  dynamic "entity_mapping" {
    for_each = each.value.entity_mappings
    content {
      entity_type = entity_mapping.value.type
      field_mapping {
        identifier  = entity_mapping.value.type == "IP" ? "Address" : entity_mapping.value.type == "Account" ? "FullName" : "HostName"
        column_name = entity_mapping.value.field
      }
    }
  }
}
