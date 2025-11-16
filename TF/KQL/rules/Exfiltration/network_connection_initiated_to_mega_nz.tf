resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_to_mega_nz" {
  name                       = "network_connection_initiated_to_mega_nz"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated To Mega.nz"
  description                = "Detects a network connection initiated by a binary to \"api.mega.co.nz\". Attackers were seen abusing file sharing websites similar to \"mega.nz\" in order to upload/download additional payloads. - Legitimate MEGA installers and utilities are expected to communicate with this domain. Exclude hosts that are known to be allowed to use this tool."
  severity                   = "Low"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl endswith "mega.co.nz" or RemoteUrl endswith "mega.nz"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1567"]
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