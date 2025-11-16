resource "azurerm_sentinel_alert_rule_scheduled" "potential_execution_of_sysinternals_tools" {
  name                       = "potential_execution_of_sysinternals_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Execution of Sysinternals Tools"
  description                = "Detects command lines that contain the 'accepteula' flag which could be a sign of execution of one of the Sysinternals tools - Legitimate use of SysInternals tools - Programs that use the same command line flag"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " -accepteula" or ProcessCommandLine contains " /accepteula" or ProcessCommandLine contains " –accepteula" or ProcessCommandLine contains " —accepteula" or ProcessCommandLine contains " ―accepteula"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1588"]
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