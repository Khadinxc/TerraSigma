resource "azurerm_sentinel_alert_rule_scheduled" "kalambur_backdoor_curl_tor_socks_proxy_execution" {
  name                       = "kalambur_backdoor_curl_tor_socks_proxy_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Kalambur Backdoor Curl TOR SOCKS Proxy Execution"
  description                = "Detects the execution of the \"curl.exe\" command, referencing \"SOCKS\" and \".onion\" domains, which could be indicative of Kalambur backdoor activity. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\curl.exe" and ProcessCommandLine contains ".onion" and (ProcessCommandLine contains "socks5h://" or ProcessCommandLine contains "socks5://" or ProcessCommandLine contains "socks4a://")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "CommandAndControl"]
  techniques                 = ["T1090", "T1573", "T1071", "T1059"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}