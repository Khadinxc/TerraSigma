resource "azurerm_sentinel_alert_rule_scheduled" "process_initiated_network_connection_to_ngrok_domain" {
  name                       = "process_initiated_network_connection_to_ngrok_domain"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Initiated Network Connection To Ngrok Domain"
  description                = "Detects an executable initiating a network connection to \"ngrok\" domains. Attackers were seen using this \"ngrok\" in order to store their second stage payloads and malware. While communication with such domains can be legitimate, often times is a sign of either data exfiltration by malicious actors or additional download. - Legitimate use of the ngrok service."
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemoteUrl endswith ".ngrok-free.app" or RemoteUrl endswith ".ngrok-free.dev" or RemoteUrl endswith ".ngrok.app" or RemoteUrl endswith ".ngrok.dev" or RemoteUrl endswith ".ngrok.io"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration", "CommandAndControl"]
  techniques                 = ["T1567", "T1572", "T1102"]
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