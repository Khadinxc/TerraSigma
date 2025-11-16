resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_event_viewer_child_process" {
  name                       = "potentially_suspicious_event_viewer_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Event Viewer Child Process"
  description                = "Detects uncommon or suspicious child processes of \"eventvwr.exe\" which might indicate a UAC bypass attempt"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\eventvwr.exe" and (not((FolderPath endswith ":\\Windows\\System32\\mmc.exe" or FolderPath endswith ":\\Windows\\System32\\WerFault.exe" or FolderPath endswith ":\\Windows\\SysWOW64\\WerFault.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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