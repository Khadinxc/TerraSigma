resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_potential_meshagent_execution_macos" {
  name                       = "remote_access_tool_potential_meshagent_execution_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - Potential MeshAgent Execution - MacOS"
  description                = "Detects potential execution of MeshAgent which is a tool used for remote access. Historical data shows that threat actors rename MeshAgent binary to evade detection. Matching command lines with the '--meshServiceName' argument can indicate that the MeshAgent is being used for remote access. - Environments that legitimately use MeshAgent"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "--meshServiceName"
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