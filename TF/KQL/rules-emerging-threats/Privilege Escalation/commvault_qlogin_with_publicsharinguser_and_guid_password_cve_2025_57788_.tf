resource "azurerm_sentinel_alert_rule_scheduled" "commvault_qlogin_with_publicsharinguser_and_guid_password_cve_2025_57788" {
  name                       = "commvault_qlogin_with_publicsharinguser_and_guid_password_cve_2025_57788"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Commvault QLogin with PublicSharingUser and GUID Password (CVE-2025-57788)"
  description                = "Detects a qlogin.exe command attempting to authenticate as the internal `_+_PublicSharingUser_` using a GUID as the password. This could be an indicator of an attacker exploiting CVE-2025-57788 to gain initial access using leaked credentials. - Legitimate administrative scripts that use the `_+_PublicSharingUser_` account for valid purposes."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "qlogin" and ProcessCommandLine contains "_+_PublicSharingUser_") and ProcessCommandLine matches regex "[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion", "InitialAccess"]
  techniques                 = ["T1078"]
  enabled                    = true

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = []
      by_alert_details        = []
      by_custom_details       = []
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}