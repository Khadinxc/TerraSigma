resource "azurerm_sentinel_alert_rule_scheduled" "potential_psexec_remote_execution" {
  name                       = "potential_psexec_remote_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PsExec Remote Execution"
  description                = "Detects potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "accepteula" and ProcessCommandLine contains " -u " and ProcessCommandLine contains " -p " and ProcessCommandLine contains " \\\\") and (not((ProcessCommandLine contains "\\\\localhost" or ProcessCommandLine contains "\\\\127.")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1587"]
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