resource "azurerm_sentinel_alert_rule_scheduled" "creation_of_non_existent_system_dll" {
  name                       = "creation_of_non_existent_system_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Creation Of Non-Existent System DLL"
  description                = "Detects the creation of system DLLs that are usually not present on the system (or at least not in system directories). Usually this technique is used to achieve DLL hijacking."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ":\\Windows\\System32\\TSMSISrv.dll" or FolderPath endswith ":\\Windows\\System32\\TSVIPSrv.dll" or FolderPath endswith ":\\Windows\\System32\\wbem\\wbemcomn.dll" or FolderPath endswith ":\\Windows\\System32\\WLBSCTRL.dll" or FolderPath endswith ":\\Windows\\System32\\wow64log.dll" or FolderPath endswith ":\\Windows\\System32\\WptsExtensions.dll" or FolderPath endswith "\\SprintCSP.dll"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
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