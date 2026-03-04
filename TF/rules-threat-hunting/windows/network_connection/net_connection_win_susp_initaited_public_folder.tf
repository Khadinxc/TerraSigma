resource "azurerm_sentinel_alert_rule_scheduled" "net_connection_win_susp_initaited_public_folder" {
  name                       = "net_connection_win_susp_initaited_public_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated From Users\\Public Folder"
  description                = "Detects a network connection initiated from a process located in the \"C:\\Users\\Public\" folder. Attacker are known to drop their malicious payloads and malware in this directory as its writable by everyone. Use this rule to hunt for potential suspicious or uncommon activity in your environement. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/network_connection/net_connection_win_susp_initaited_public_folder.yml - Likely from legitimate third party application that execute from the \"Public\" directory. | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/network_connection/net_connection_win_susp_initaited_public_folder.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath contains ":\\Users\\Public\\" and (not(InitiatingProcessFolderPath contains ":\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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