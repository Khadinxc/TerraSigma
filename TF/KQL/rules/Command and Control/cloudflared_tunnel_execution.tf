resource "azurerm_sentinel_alert_rule_scheduled" "cloudflared_tunnel_execution" {
  name                       = "cloudflared_tunnel_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cloudflared Tunnel Execution"
  description                = "Detects execution of the \"cloudflared\" tool to connect back to a tunnel. This was seen used by threat actors to maintain persistence and remote access to compromised networks. - Legitimate usage of Cloudflared tunnel."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-config " or ProcessCommandLine contains "-credentials-contents " or ProcessCommandLine contains "-credentials-file " or ProcessCommandLine contains "-token ") and (ProcessCommandLine contains " tunnel " and ProcessCommandLine contains " run ")
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