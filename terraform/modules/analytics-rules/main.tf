locals {
  detection_files = {
    brute_force_signin = {
      file        = "${var.detections_path}/credential-access/brute-force-signin.kql"
      name        = "Brute Force Sign-in Attempts"
      description = "Detects multiple failed sign-in attempts from a single IP within 1 hour"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["CredentialAccess"]
      techniques  = ["T1110"]
      entity_mappings = {
        ip = { type = "IP", field = "Entity_IP" }
      }
      custom_details = {
        SourceIP       = "Entity_IP"
        FailedAttempts = "FailedAttempts"
      }
    }
    password_spray = {
      file        = "${var.detections_path}/credential-access/password-spray.kql"
      name        = "Password Spray Attack"
      description = "Detects a single IP attempting sign-ins against multiple distinct accounts"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["CredentialAccess"]
      techniques  = ["T1110"]
      entity_mappings = {
        ip = { type = "IP", field = "Entity_IP" }
      }
      custom_details = {
        SourceIP        = "Entity_IP"
        DistinctTargets = "DistinctAccounts"
      }
    }
    impossible_travel = {
      file        = "${var.detections_path}/credential-access/impossible-travel.kql"
      name        = "Impossible Travel Sign-in"
      description = "Detects a user signing in from geographically distant locations in a short time"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT24H"
      tactics     = ["InitialAccess"]
      techniques  = ["T1078"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
      }
      custom_details = {
        Account       = "Entity_Account"
        DistanceKm    = "DistanceKm"
        RequiredSpeed = "RequiredSpeedKmH"
      }
    }
    phishing_inbox_rule = {
      file        = "${var.detections_path}/initial-access/phishing-inbox-rule.kql"
      name        = "Suspicious Inbox Rule Created (Phishing Indicator)"
      description = "Detects creation of inbox rules that move or delete items post-compromise"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["InitialAccess"]
      techniques  = ["T1566"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
        ip      = { type = "IP", field = "Entity_IP" }
      }
      custom_details = {
        Account  = "Entity_Account"
        RuleName = "RuleName"
      }
    }
    suspicious_oauth_consent = {
      file        = "${var.detections_path}/initial-access/suspicious-oauth-consent.kql"
      name        = "Suspicious OAuth Application Consent"
      description = "Detects OAuth application consent grants with high-privilege permissions"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["InitialAccess"]
      techniques  = ["T1566"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
        ip      = { type = "IP", field = "Entity_IP" }
      }
      custom_details = {
        Account = "Entity_Account"
        AppName = "AppDisplayName"
      }
    }
    new_inbox_forwarding_rule = {
      file        = "${var.detections_path}/persistence/new-inbox-forwarding-rule.kql"
      name        = "New Inbox Forwarding Rule to External Domain"
      description = "Detects creation of email forwarding rules to external addresses"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["Persistence"]
      techniques  = ["T1137"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
        ip      = { type = "IP", field = "Entity_IP" }
      }
      custom_details = {
        Account           = "Entity_Account"
        ForwardingAddress = "ForwardingAddress"
      }
    }
    suspicious_service_principal = {
      file        = "${var.detections_path}/persistence/suspicious-service-principal.kql"
      name        = "Suspicious Service Principal Creation"
      description = "Detects creation of new service principals or app registrations"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["Persistence"]
      techniques  = ["T1136"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
        ip      = { type = "IP", field = "Entity_IP" }
      }
      custom_details = {
        Account   = "Entity_Account"
        Operation = "OperationName"
      }
    }
    anomalous_rdp_signin = {
      file        = "${var.detections_path}/lateral-movement/anomalous-rdp-signin.kql"
      name        = "Anomalous RDP Sign-in"
      description = "Detects RDP sign-ins from unusual source IPs or during off-hours"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["LateralMovement"]
      techniques  = ["T1021"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
        ip      = { type = "IP", field = "Entity_IP" }
      }
      custom_details = {
        Account      = "Entity_Account"
        SourceIP     = "Entity_IP"
        AnomalyScore = "AnomalyScore"
      }
    }
    multi_host_admin_logon = {
      file        = "${var.detections_path}/lateral-movement/multi-host-admin-logon.kql"
      name        = "Multi-Host Admin Logon"
      description = "Detects a single account performing admin logons across multiple hosts"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["LateralMovement", "PrivilegeEscalation"]
      techniques  = ["T1078"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
      }
      custom_details = {
        Account   = "Entity_Account"
        HostCount = "DistinctHostCount"
      }
    }
    bulk_file_download = {
      file        = "${var.detections_path}/exfiltration/bulk-file-download.kql"
      name        = "Bulk File Download from SharePoint/OneDrive"
      description = "Detects bulk file downloads from SharePoint or OneDrive"
      severity    = "Medium"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["Exfiltration"]
      techniques  = ["T1567"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
      }
      custom_details = {
        Account       = "Entity_Account"
        DownloadCount = "DownloadCount"
      }
    }
    mail_forwarding_to_external = {
      file        = "${var.detections_path}/exfiltration/mail-forwarding-to-external.kql"
      name        = "Mail Forwarding to External Domain"
      description = "Detects email auto-forwarding configured to external domains"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["Collection", "Exfiltration"]
      techniques  = ["T1114"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
        ip      = { type = "IP", field = "Entity_IP" }
      }
      custom_details = {
        Account           = "Entity_Account"
        ForwardingAddress = "ForwardingAddress"
      }
    }
    encoded_powershell = {
      file        = "${var.detections_path}/defense-evasion/encoded-powershell.kql"
      name        = "Encoded PowerShell Execution"
      description = "Detects execution of encoded PowerShell commands"
      severity    = "High"
      frequency   = "PT1H"
      period      = "PT1H"
      tactics     = ["DefenseEvasion"]
      techniques  = ["T1027"]
      entity_mappings = {
        account = { type = "Account", field = "Entity_Account" }
        host    = { type = "Host", field = "Entity_Host" }
      }
      custom_details = {
        Account = "Entity_Account"
        Host    = "Entity_Host"
      }
    }
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "detection" {
  for_each = local.detection_files

  name                       = each.key
  display_name               = each.value.name
  log_analytics_workspace_id = var.workspace_id
  description                = each.value.description
  severity                   = each.value.severity
  enabled                    = true
  query                      = file(each.value.file)
  query_frequency            = each.value.frequency
  query_period               = each.value.period
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = true
  suppression_duration       = "PT1H"
  tactics                    = each.value.tactics
  techniques                 = each.value.techniques
  custom_details             = each.value.custom_details

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = [for k, v in each.value.entity_mappings : v.type]
      by_custom_details       = keys(each.value.custom_details)
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
