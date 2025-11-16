resource "azurerm_sentinel_alert_rule_scheduled" "wscript_shell_run_in_commandline" {
  name                       = "wscript_shell_run_in_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wscript Shell Run In CommandLine"
  description                = "Detects the presence of the keywords \"Wscript\", \"Shell\" and \"Run\" in the command, which could indicate a suspicious activity - Inline scripting can be used by some rare third party applications or administrators. Investigate and apply additional filters accordingly"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Wscript." and ProcessCommandLine contains ".Shell" and ProcessCommandLine contains ".Run"
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
  }
}