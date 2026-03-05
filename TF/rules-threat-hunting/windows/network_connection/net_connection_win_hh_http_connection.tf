resource "azurerm_sentinel_alert_rule_scheduled" "net_connection_win_hh_http_connection" {
  name                       = "net_connection_win_hh_http_connection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HH.EXE Initiated HTTP Network Connection"
  description                = <<DESC
    Detects a network connection initiated by the "hh.exe" process to HTTP destination ports, which could indicate the execution/download of remotely hosted .chm files.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/network_connection/net_connection_win_hh_http_connection.yml

    False Positives:
    - False positive is expected from launching "hh.exe" for the first time on a machine in a while or simply from help files containing reference to external sources. Best correlate this with process creation and file events.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemotePort in~ ("80", "443")) and InitiatingProcessFolderPath endswith "\\hh.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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