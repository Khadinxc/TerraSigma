resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_files_in_default_gpo_folder" {
  name                       = "suspicious_files_in_default_gpo_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Files in Default GPO Folder"
  description                = "Detects the creation of copy of suspicious files (EXE/DLL) to the default GPO storage folder"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\" and (FolderPath endswith ".dll" or FolderPath endswith ".exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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