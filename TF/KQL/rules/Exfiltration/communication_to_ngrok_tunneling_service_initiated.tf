resource "azurerm_sentinel_alert_rule_scheduled" "communication_to_ngrok_tunneling_service_initiated" {
  name                       = "communication_to_ngrok_tunneling_service_initiated"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Communication To Ngrok Tunneling Service Initiated"
  description                = "Detects an executable initiating a network connection to \"ngrok\" tunneling domains. Attackers were seen using this \"ngrok\" in order to store their second stage payloads and malware. While communication with such domains can be legitimate, often times is a sign of either data exfiltration by malicious actors or additional download. - Legitimate use of the ngrok service."
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