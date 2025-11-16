resource "azurerm_sentinel_alert_rule_scheduled" "malicious_dll_file_dropped_in_the_teams_or_onedrive_folder" {
  name                       = "malicious_dll_file_dropped_in_the_teams_or_onedrive_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Malicious DLL File Dropped in the Teams or OneDrive Folder"
  description                = "Detects creation of a malicious DLL file in the location where the OneDrive or Team applications Upon execution of the Teams or OneDrive application, the dropped malicious DLL file (\"iphlpapi.dll\") is sideloaded"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "iphlpapi.dll" and FolderPath contains "\\AppData\\Local\\Microsoft"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1574"]
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