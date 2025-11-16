resource "azurerm_sentinel_alert_rule_scheduled" "new_process_created_via_taskmgr_exe" {
  name                       = "new_process_created_via_taskmgr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Process Created Via Taskmgr.EXE"
  description                = "Detects the creation of a process via the Windows task manager. This might be an attempt to bypass UAC - Administrative activity"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\taskmgr.exe" and (not((FolderPath endswith ":\\Windows\\System32\\mmc.exe" or FolderPath endswith ":\\Windows\\System32\\resmon.exe" or FolderPath endswith ":\\Windows\\System32\\Taskmgr.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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