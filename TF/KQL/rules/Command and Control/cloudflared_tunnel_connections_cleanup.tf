resource "azurerm_sentinel_alert_rule_scheduled" "cloudflared_tunnel_connections_cleanup" {
  name                       = "cloudflared_tunnel_connections_cleanup"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cloudflared Tunnel Connections Cleanup"
  description                = "Detects execution of the \"cloudflared\" tool with the tunnel \"cleanup\" flag in order to cleanup tunnel connections. - Legitimate usage of Cloudflared."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-config " or ProcessCommandLine contains "-connector-id ") and (ProcessCommandLine contains " tunnel " and ProcessCommandLine contains "cleanup ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1102", "T1090", "T1572"]
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