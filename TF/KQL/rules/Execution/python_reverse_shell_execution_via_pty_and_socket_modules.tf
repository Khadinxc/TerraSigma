resource "azurerm_sentinel_alert_rule_scheduled" "python_reverse_shell_execution_via_pty_and_socket_modules" {
  name                       = "python_reverse_shell_execution_via_pty_and_socket_modules"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python Reverse Shell Execution Via PTY And Socket Modules"
  description                = "Detects the execution of python with calls to the socket and pty module in order to connect and spawn a potential reverse shell."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -c " and ProcessCommandLine contains "import" and ProcessCommandLine contains "pty" and ProcessCommandLine contains "socket" and ProcessCommandLine contains "spawn" and ProcessCommandLine contains ".connect") and FolderPath contains "python"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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