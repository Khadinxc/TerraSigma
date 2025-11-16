resource "azurerm_sentinel_alert_rule_scheduled" "visual_studio_code_tunnel_service_installation" {
  name                       = "visual_studio_code_tunnel_service_installation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Visual Studio Code Tunnel Service Installation"
  description                = "Detects the installation of VsCode tunnel (code-tunnel) as a service. - Legitimate installation of code-tunnel as a service"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "tunnel " and ProcessCommandLine contains "service" and ProcessCommandLine contains "internal-run" and ProcessCommandLine contains "tunnel-service.log"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1071"]
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