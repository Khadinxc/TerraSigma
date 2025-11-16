resource "azurerm_sentinel_alert_rule_scheduled" "msexchange_transport_agent_installation" {
  name                       = "msexchange_transport_agent_installation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "MSExchange Transport Agent Installation"
  description                = "Detects the Installation of a Exchange Transport Agent - Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Install-TransportAgent"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1505"]
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