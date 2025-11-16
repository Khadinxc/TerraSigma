resource "azurerm_sentinel_alert_rule_scheduled" "winrar_creating_files_in_startup_locations" {
  name                       = "winrar_creating_files_in_startup_locations"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WinRAR Creating Files in Startup Locations"
  description                = "Detects WinRAR creating files in Windows startup locations, which may indicate an attempt to establish persistence by adding malicious files to the Startup folder. This kind of behaviour has been associated with exploitation of WinRAR path traversal vulnerability CVE-2025-6218 or CVE-2025-8088."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\WinRAR.exe" or InitiatingProcessFolderPath endswith "\\Rar.exe") and FolderPath contains "\\Start Menu\\Programs\\Startup\\"
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