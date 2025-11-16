resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_sideloading_via_comctl32_dll" {
  name                       = "potential_dll_sideloading_via_comctl32_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Sideloading Via comctl32.dll"
  description                = "Detects potential DLL sideloading using comctl32.dll to obtain system privileges - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\comctl32.dll" and (FolderPath startswith "C:\\Windows\\System32\\logonUI.exe.local\\" or FolderPath startswith "C:\\Windows\\System32\\werFault.exe.local\\" or FolderPath startswith "C:\\Windows\\System32\\consent.exe.local\\" or FolderPath startswith "C:\\Windows\\System32\\narrator.exe.local\\" or FolderPath startswith "C:\\windows\\system32\\wermgr.exe.local\\")
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