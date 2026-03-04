resource "azurerm_sentinel_alert_rule_scheduled" "net_connection_win_domain_portmap" {
  name                       = "net_connection_win_domain_portmap"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Communication Initiated To Portmap.IO Domain"
  description                = "Detects an executable accessing the portmap.io domain, which could be a sign of forbidden C2 traffic or data exfiltration by malicious actors Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_portmap.yml - Legitimate use of portmap.io domains | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_portmap.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl endswith ".portmap.io"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "Exfiltration"]
  techniques                 = ["T1041", "T1090"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "RemoteIP"
    }
  }

  entity_mapping {
    entity_type = "URL"
    field_mapping {
      identifier  = "Url"
      column_name = "RemoteUrl"
    }
  }
}