resource "azurerm_sentinel_alert_rule_scheduled" "lazarus_apt_dll_sideloading_activity" {
  name                       = "lazarus_apt_dll_sideloading_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Lazarus APT DLL Sideloading Activity"
  description                = "Detects sideloading of trojanized DLLs used in Lazarus APT campaign in the case of a Spanish aerospace company - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (InitiatingProcessFolderPath =~ "C:\\ProgramData\\Adobe\\colorcpl.exe" and FolderPath =~ "C:\\ProgramData\\Adobe\\colorui.dll") or (InitiatingProcessFolderPath =~ "C:\\ProgramData\\Adobe\\ARM\\tabcal.exe" and FolderPath =~ "C:\\ProgramData\\Adobe\\ARM\\HID.dll") or (InitiatingProcessFolderPath =~ "C:\\ProgramData\\Oracle\\Java\\fixmapi.exe" and FolderPath =~ "C:\\ProgramData\\Oracle\\Java\\mapistub.dll") or (InitiatingProcessFolderPath =~ "C:\\ProgramShared\\PresentationHost.exe" and FolderPath =~ ":\\ProgramShared\\mscoree.dll")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation", "Persistence"]
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