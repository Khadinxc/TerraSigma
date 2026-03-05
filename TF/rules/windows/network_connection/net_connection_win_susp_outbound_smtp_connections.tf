resource "azurerm_sentinel_alert_rule_scheduled" "net_connection_win_susp_outbound_smtp_connections" {
  name                       = "net_connection_win_susp_outbound_smtp_connections"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Outbound SMTP Connections"
  description                = <<DESC
    Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_susp_outbound_smtp_connections.yml

    False Positives:
    - Other SMTP tools
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemotePort in~ ("25", "587", "465", "2525")) and (not(((InitiatingProcessFolderPath endswith "\\thunderbird.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe") or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft\\Exchange Server\\" or (InitiatingProcessFolderPath endswith "\\HxTsr.exe" and InitiatingProcessFolderPath startswith "C:\\Program Files\\WindowsApps\\microsoft.windowscommunicationsapps_"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1048"]
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