resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_process_start_locations" {
  name                       = "suspicious_process_start_locations"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process Start Locations"
  description                = "Detects suspicious process run from unusual locations"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains ":\\RECYCLER\\" or FolderPath contains ":\\SystemVolumeInformation\\") or (FolderPath startswith "C:\\Windows\\Tasks\\" or FolderPath startswith "C:\\Windows\\debug\\" or FolderPath startswith "C:\\Windows\\fonts\\" or FolderPath startswith "C:\\Windows\\help\\" or FolderPath startswith "C:\\Windows\\drivers\\" or FolderPath startswith "C:\\Windows\\addins\\" or FolderPath startswith "C:\\Windows\\cursors\\" or FolderPath startswith "C:\\Windows\\system32\\tasks\\")
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