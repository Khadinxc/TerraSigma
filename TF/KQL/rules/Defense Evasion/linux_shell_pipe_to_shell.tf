resource "azurerm_sentinel_alert_rule_scheduled" "linux_shell_pipe_to_shell" {
  name                       = "linux_shell_pipe_to_shell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Shell Pipe to Shell"
  description                = "Detects suspicious process command line that starts with a shell that executes something and finally gets piped into another shell - Legitimate software that uses these patterns"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine startswith "sh -c " or ProcessCommandLine startswith "bash -c ") and ((ProcessCommandLine contains "| bash " or ProcessCommandLine contains "| sh " or ProcessCommandLine contains "|bash " or ProcessCommandLine contains "|sh ") or (ProcessCommandLine endswith "| bash" or ProcessCommandLine endswith "| sh" or ProcessCommandLine endswith "|bash" or ProcessCommandLine endswith " |sh"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1140"]
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
  }
}