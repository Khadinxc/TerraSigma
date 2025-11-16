resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_sigverif_exe_child_process" {
  name                       = "uncommon_sigverif_exe_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Sigverif.EXE Child Process"
  description                = "Detects uncommon child processes spawning from \"sigverif.exe\", which could indicate potential abuse of the latter as a living of the land binary in order to proxy execution."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\sigverif.exe" and (not((FolderPath in~ ("C:\\Windows\\System32\\WerFault.exe", "C:\\Windows\\SysWOW64\\WerFault.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1216"]
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