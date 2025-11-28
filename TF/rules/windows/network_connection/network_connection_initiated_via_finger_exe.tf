resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_via_finger_exe" {
  name                       = "network_connection_initiated_via_finger_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated via Finger.EXE"
  description                = "Detects network connections via finger.exe, which can be abused by threat actors to retrieve remote commands for execution on Windows devices. In one ClickFix malware campaign, adversaries leveraged the finger protocol to fetch commands from a remote server. Since the finger utility is not commonly used in modern Windows environments, its presence already raises suspicion. Investigating such network connections can also help identify potential malicious infrastructure used by threat actors - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\finger.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "Execution"]
  techniques                 = ["T1071", "T1059"]
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
}