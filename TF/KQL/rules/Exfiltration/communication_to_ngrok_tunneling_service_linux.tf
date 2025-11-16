resource "azurerm_sentinel_alert_rule_scheduled" "communication_to_ngrok_tunneling_service_linux" {
  name                       = "communication_to_ngrok_tunneling_service_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Communication To Ngrok Tunneling Service - Linux"
  description                = "Detects an executable accessing an ngrok tunneling endpoint, which could be a sign of forbidden exfiltration of data exfiltration by malicious actors - Legitimate use of ngrok"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl contains "tunnel.us.ngrok.com" or RemoteUrl contains "tunnel.eu.ngrok.com" or RemoteUrl contains "tunnel.ap.ngrok.com" or RemoteUrl contains "tunnel.au.ngrok.com" or RemoteUrl contains "tunnel.sa.ngrok.com" or RemoteUrl contains "tunnel.jp.ngrok.com" or RemoteUrl contains "tunnel.in.ngrok.com"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration", "CommandAndControl"]
  techniques                 = ["T1567", "T1568", "T1572", "T1090", "T1102"]
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
    entity_type = "URL"
    field_mapping {
      identifier  = "Url"
      column_name = "RemoteUrl"
    }
  }
}