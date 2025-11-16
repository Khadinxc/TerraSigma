resource "azurerm_sentinel_alert_rule_scheduled" "darkgate_drop_darkgate_loader_in_c_temp_directory" {
  name                       = "darkgate_drop_darkgate_loader_in_c_temp_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DarkGate - Drop DarkGate Loader In C:\\Temp Directory"
  description                = "Detects attackers attempting to save, decrypt and execute the DarkGate Loader in C:\\temp folder. - Unlikely legitimate usage of AutoIT in temp folders."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains ":\\temp\\" and (FolderPath endswith ".au3" or FolderPath endswith "\\autoit3.exe")) or (InitiatingProcessFolderPath contains ":\\temp\\" and (InitiatingProcessFolderPath endswith ".au3" or InitiatingProcessFolderPath endswith "\\autoit3.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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