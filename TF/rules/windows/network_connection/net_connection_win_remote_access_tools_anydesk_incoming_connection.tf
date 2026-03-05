resource "azurerm_sentinel_alert_rule_scheduled" "net_connection_win_remote_access_tools_anydesk_incoming_connection" {
  name                       = "net_connection_win_remote_access_tools_anydesk_incoming_connection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - AnyDesk Incoming Connection"
  description                = <<DESC
    Detects incoming connections to AnyDesk. This could indicate a potential remote attacker trying to connect to a listening instance of AnyDesk and use it as potential command and control channel.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_remote_access_tools_anydesk_incoming_connection.yml

    False Positives:
    - Legitimate incoming connections (e.g. sysadmin activity). Most of the time I would expect outgoing connections (initiated locally).
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\AnyDesk.exe" or InitiatingProcessFolderPath endswith "\\AnyDeskMSI.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "CommandAndControl"]
  techniques                 = ["T1219"]
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
}