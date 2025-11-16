resource "azurerm_sentinel_alert_rule_scheduled" "potential_actinium_persistence_activity" {
  name                       = "potential_actinium_persistence_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential ACTINIUM Persistence Activity"
  description                = "Detects specific process parameters as used by ACTINIUM scheduled task persistence creation. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "create" and ProcessCommandLine contains "wscript" and ProcessCommandLine contains " /e:vbscript"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053"]
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