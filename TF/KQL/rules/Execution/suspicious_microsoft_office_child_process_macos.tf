resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_microsoft_office_child_process_macos" {
  name                       = "suspicious_microsoft_office_child_process_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Microsoft Office Child Process - MacOS"
  description                = "Detects suspicious child processes spawning from microsoft office suite applications such as word or excel. This could indicates malicious macro execution"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "/bash" or FolderPath endswith "/curl" or FolderPath endswith "/dash" or FolderPath endswith "/fish" or FolderPath endswith "/osacompile" or FolderPath endswith "/osascript" or FolderPath endswith "/sh" or FolderPath endswith "/zsh" or FolderPath endswith "/python" or FolderPath endswith "/python3" or FolderPath endswith "/wget") and (InitiatingProcessFolderPath contains "Microsoft Word" or InitiatingProcessFolderPath contains "Microsoft Excel" or InitiatingProcessFolderPath contains "Microsoft PowerPoint" or InitiatingProcessFolderPath contains "Microsoft OneNote")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence"]
  techniques                 = ["T1059", "T1137", "T1204"]
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