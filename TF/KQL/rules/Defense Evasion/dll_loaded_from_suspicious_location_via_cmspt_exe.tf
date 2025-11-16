resource "azurerm_sentinel_alert_rule_scheduled" "dll_loaded_from_suspicious_location_via_cmspt_exe" {
  name                       = "dll_loaded_from_suspicious_location_via_cmspt_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DLL Loaded From Suspicious Location Via Cmspt.EXE"
  description                = "Detects cmstp loading \"dll\" or \"ocx\" files from suspicious locations - Unikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath contains "\\PerfLogs\\" or FolderPath contains "\\ProgramData\\" or FolderPath contains "\\Users\\" or FolderPath contains "\\Windows\\Temp\\" or FolderPath contains "C:\\Temp\\") and (FolderPath endswith ".dll" or FolderPath endswith ".ocx") and InitiatingProcessFolderPath endswith "\\cmstp.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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