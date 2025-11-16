resource "azurerm_sentinel_alert_rule_scheduled" "pua_nircmd_execution_as_local_system" {
  name                       = "pua_nircmd_execution_as_local_system"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - NirCmd Execution As LOCAL SYSTEM"
  description                = "Detects the use of NirCmd tool for command execution as SYSTEM user - Legitimate use by administrators"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " runassystem "
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1569"]
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