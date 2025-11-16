resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_crackmapexec_file_indicators" {
  name                       = "hacktool_crackmapexec_file_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - CrackMapExec File Indicators"
  description                = "Detects file creation events with filename patterns used by CrackMapExec."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath startswith "C:\\Windows\\Temp\\" and ((FolderPath matches regex "\\\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.txt$" or FolderPath matches regex "\\\\[a-zA-Z]{8}\\.tmp$") or (FolderPath endswith "\\temp.ps1" or FolderPath endswith "\\msol.ps1"))
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