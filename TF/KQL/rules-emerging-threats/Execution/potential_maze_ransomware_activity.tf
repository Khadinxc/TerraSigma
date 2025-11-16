resource "azurerm_sentinel_alert_rule_scheduled" "potential_maze_ransomware_activity" {
  name                       = "potential_maze_ransomware_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Maze Ransomware Activity"
  description                = "Detects specific process characteristics of Maze ransomware word document droppers - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith ".tmp" and InitiatingProcessFolderPath endswith "\\WINWORD.exe") or (ProcessCommandLine endswith "shadowcopy delete" and FolderPath endswith "\\wmic.exe" and InitiatingProcessFolderPath contains "\\Temp\\") or (ProcessCommandLine contains "\\..\\..\\system32" and ProcessCommandLine endswith "shadowcopy delete")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Impact"]
  techniques                 = ["T1204", "T1047", "T1490"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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