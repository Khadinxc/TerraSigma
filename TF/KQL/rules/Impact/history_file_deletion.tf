resource "azurerm_sentinel_alert_rule_scheduled" "history_file_deletion" {
  name                       = "history_file_deletion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "History File Deletion"
  description                = "Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity - Legitimate administration activities"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "/rm" or FolderPath endswith "/unlink" or FolderPath endswith "/shred") and ((ProcessCommandLine contains "/.bash_history" or ProcessCommandLine contains "/.zsh_history") or (ProcessCommandLine endswith "_history" or ProcessCommandLine endswith ".history" or ProcessCommandLine endswith "zhistory"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1565"]
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