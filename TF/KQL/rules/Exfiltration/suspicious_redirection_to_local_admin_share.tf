resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_redirection_to_local_admin_share" {
  name                       = "suspicious_redirection_to_local_admin_share"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Redirection to Local Admin Share"
  description                = "Detects a suspicious output redirection to the local admins share, this technique is often found in malicious scripts or hacktool stagers"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains ">" and (ProcessCommandLine contains "\\\\127.0.0.1\\admin$\\" or ProcessCommandLine contains "\\\\localhost\\admin$\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1048"]
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