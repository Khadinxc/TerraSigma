resource "azurerm_sentinel_alert_rule_scheduled" "python_spawning_pretty_tty_via_pty_module" {
  name                       = "python_spawning_pretty_tty_via_pty_module"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python Spawning Pretty TTY Via PTY Module"
  description                = "Detects a python process calling to the PTY module in order to spawn a pretty tty which could be indicative of potential reverse shell activity."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "import pty" or ProcessCommandLine contains "from pty ") and ProcessCommandLine contains "spawn" and ((FolderPath endswith "/python" or FolderPath endswith "/python2" or FolderPath endswith "/python3") or (FolderPath contains "/python2." or FolderPath contains "/python3."))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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