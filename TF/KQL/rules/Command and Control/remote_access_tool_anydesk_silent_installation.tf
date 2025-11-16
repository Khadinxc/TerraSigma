resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_anydesk_silent_installation" {
  name                       = "remote_access_tool_anydesk_silent_installation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - AnyDesk Silent Installation"
  description                = "Detects AnyDesk Remote Desktop silent installation. Which can be used by attackers to gain remote access. - Legitimate deployment of AnyDesk"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "--install" and ProcessCommandLine contains "--start-with-win" and ProcessCommandLine contains "--silent"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]
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