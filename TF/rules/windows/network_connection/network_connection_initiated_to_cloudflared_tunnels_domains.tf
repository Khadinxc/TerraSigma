resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_to_cloudflared_tunnels_domains" {
  name                       = "network_connection_initiated_to_cloudflared_tunnels_domains"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated To Cloudflared Tunnels Domains"
  description                = "Detects network connections to Cloudflared tunnels domains initiated by a process on the system. Attackers can abuse that feature to establish a reverse shell or persistence on a machine. - Legitimate use of cloudflare tunnels will also trigger this."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl endswith ".v2.argotunnel.com" or RemoteUrl endswith "protocol-v2.argotunnel.com" or RemoteUrl endswith "trycloudflare.com" or RemoteUrl endswith "update.argotunnel.com"
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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