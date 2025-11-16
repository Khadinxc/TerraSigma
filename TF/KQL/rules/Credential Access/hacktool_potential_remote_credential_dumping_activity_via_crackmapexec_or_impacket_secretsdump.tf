resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_potential_remote_credential_dumping_activity_via_crackmapexec_or_impacket_secretsdump" {
  name                       = "hacktool_potential_remote_credential_dumping_activity_via_crackmapexec_or_impacket_secretsdump"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump"
  description                = "Detects default filenames output from the execution of CrackMapExec and Impacket-secretsdump against an endpoint."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\svchost.exe" and FolderPath matches regex "\\\\Windows\\\\System32\\\\[a-zA-Z0-9]{8}\\.tmp$"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}