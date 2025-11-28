resource "azurerm_sentinel_alert_rule_scheduled" "linux_crypto_mining_pool_connections" {
  name                       = "linux_crypto_mining_pool_connections"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Crypto Mining Pool Connections"
  description                = "Detects process connections to a Monero crypto mining pool - Legitimate use of crypto miners"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl in~ ("pool.minexmr.com", "fr.minexmr.com", "de.minexmr.com", "sg.minexmr.com", "ca.minexmr.com", "us-west.minexmr.com", "pool.supportxmr.com", "mine.c3pool.com", "xmr-eu1.nanopool.org", "xmr-eu2.nanopool.org", "xmr-us-east1.nanopool.org", "xmr-us-west1.nanopool.org", "xmr-asia1.nanopool.org", "xmr-jp1.nanopool.org", "xmr-au1.nanopool.org", "xmr.2miners.com", "xmr.hashcity.org", "xmr.f2pool.com", "xmrpool.eu", "pool.hashvault.pro", "moneroocean.stream", "monerocean.stream")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1496"]
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