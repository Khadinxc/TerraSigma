resource "azurerm_sentinel_alert_rule_scheduled" "potential_rjvplatform_dll_sideloading_from_default_location" {
  name                       = "potential_rjvplatform_dll_sideloading_from_default_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential RjvPlatform.DLL Sideloading From Default Location"
  description                = "Detects loading of \"RjvPlatform.dll\" by the \"SystemResetPlatform.exe\" binary which can be abused as a method of DLL side loading since the \"$SysReset\" directory isn't created by default."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\SystemResetPlatform\\SystemResetPlatform.exe" and FolderPath =~ "C:\\$SysReset\\Framework\\Stack\\RjvPlatform.dll"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
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