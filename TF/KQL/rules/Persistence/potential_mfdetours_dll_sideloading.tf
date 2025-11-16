resource "azurerm_sentinel_alert_rule_scheduled" "potential_mfdetours_dll_sideloading" {
  name                       = "potential_mfdetours_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Mfdetours.DLL Sideloading"
  description                = "Detects potential DLL sideloading of \"mfdetours.dll\". While using \"mftrace.exe\" it can be abused to attach to an arbitrary process and force load any DLL named \"mfdetours.dll\" from the current directory of execution. - Unlikely"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\mfdetours.dll" and (not(FolderPath contains ":\\Program Files (x86)\\Windows Kits\\10\\bin\\"))
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