resource "azurerm_sentinel_alert_rule_scheduled" "etw_logging_tamper_in_net_processes_via_commandline" {
  name                       = "etw_logging_tamper_in_net_processes_via_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ETW Logging Tamper In .NET Processes Via CommandLine"
  description                = "Detects changes to environment variables related to ETW logging via the CommandLine. This could indicate potential adversaries stopping ETW providers recording loaded .NET assemblies. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "COMPlus_ETWEnabled" or ProcessCommandLine contains "COMPlus_ETWFlags"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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