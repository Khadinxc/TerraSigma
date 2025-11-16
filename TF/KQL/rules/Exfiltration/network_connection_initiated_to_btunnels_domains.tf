resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_to_btunnels_domains" {
  name                       = "network_connection_initiated_to_btunnels_domains"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated To BTunnels Domains"
  description                = "Detects network connections to BTunnels domains initiated by a process on the system. Attackers can abuse that feature to establish a reverse shell or persistence on a machine. - Legitimate use of BTunnels will also trigger this."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl endswith ".btunnel.co.in"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration", "CommandAndControl"]
  techniques                 = ["T1567", "T1572"]
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