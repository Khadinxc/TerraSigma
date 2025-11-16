resource "azurerm_sentinel_alert_rule_scheduled" "file_creation_in_suspicious_directory_by_msdt_exe" {
  name                       = "file_creation_in_suspicious_directory_by_msdt_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Creation In Suspicious Directory By Msdt.EXE"
  description                = "Detects msdt.exe creating files in suspicious directories which could be a sign of exploitation of either Follina or Dogwalk vulnerabilities"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\msdt.exe" and (FolderPath contains "\\Desktop\\" or FolderPath contains "\\Start Menu\\Programs\\Startup\\" or FolderPath contains "C:\\PerfLogs\\" or FolderPath contains "C:\\ProgramData\\" or FolderPath contains "C:\\Users\\Public\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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