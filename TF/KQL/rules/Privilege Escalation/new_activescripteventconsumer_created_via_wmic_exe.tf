resource "azurerm_sentinel_alert_rule_scheduled" "new_activescripteventconsumer_created_via_wmic_exe" {
  name                       = "new_activescripteventconsumer_created_via_wmic_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New ActiveScriptEventConsumer Created Via Wmic.EXE"
  description                = "Detects WMIC executions in which an event consumer gets created. This could be used to establish persistence - Legitimate software creating script event consumers"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "ActiveScriptEventConsumer" and ProcessCommandLine contains " CREATE "
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1546"]
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