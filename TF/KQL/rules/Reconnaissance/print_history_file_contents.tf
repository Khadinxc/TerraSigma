resource "azurerm_sentinel_alert_rule_scheduled" "print_history_file_contents" {
  name                       = "print_history_file_contents"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Print History File Contents"
  description                = "Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "/cat" or FolderPath endswith "/head" or FolderPath endswith "/tail" or FolderPath endswith "/more") and ((ProcessCommandLine contains "/.bash_history" or ProcessCommandLine contains "/.zsh_history") or (ProcessCommandLine endswith "_history" or ProcessCommandLine endswith ".history" or ProcessCommandLine endswith "zhistory"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Reconnaissance"]
  techniques                 = ["T1592"]
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