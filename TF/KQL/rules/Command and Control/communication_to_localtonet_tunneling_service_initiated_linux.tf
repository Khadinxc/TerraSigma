resource "azurerm_sentinel_alert_rule_scheduled" "communication_to_localtonet_tunneling_service_initiated_linux" {
  name                       = "communication_to_localtonet_tunneling_service_initiated_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Communication To LocaltoNet Tunneling Service Initiated - Linux"
  description                = "Detects an executable initiating a network connection to \"LocaltoNet\" tunneling sub-domains. LocaltoNet is a reverse proxy that enables localhost services to be exposed to the Internet. Attackers have been seen to use this service for command-and-control activities to bypass MFA and perimeter controls. - Legitimate use of the LocaltoNet service."
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl endswith ".localto.net" or RemoteUrl endswith ".localtonet.com"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1572", "T1090", "T1102"]
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