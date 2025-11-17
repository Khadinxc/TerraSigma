resource "azurerm_sentinel_alert_rule_scheduled" "obfuscated_ip_via_cli" {
  name                       = "obfuscated_ip_via_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Obfuscated IP Via CLI"
  description                = "Detects usage of an encoded/obfuscated version of an IP address (hex, octal, etc.) via command line"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\ping.exe" or FolderPath endswith "\\arp.exe") and ((ProcessCommandLine contains " 0x" or ProcessCommandLine contains "//0x" or ProcessCommandLine contains ".0x" or ProcessCommandLine contains ".00x") or (ProcessCommandLine contains "http://%" and ProcessCommandLine contains "%2e") or (ProcessCommandLine matches regex "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}" or ProcessCommandLine matches regex "https?://[0-9]{1,3}\\.0[0-9]{3,7}" or ProcessCommandLine matches regex "https?://0[0-9]{3,11}" or ProcessCommandLine matches regex "https?://(0[0-9]{1,11}\\.){3}0[0-9]{1,11}" or ProcessCommandLine matches regex "https?://0[0-9]{1,11}" or ProcessCommandLine matches regex " [0-7]{7,13}")) and (not(ProcessCommandLine matches regex "https?://((25[0-5]|(2[0-4]|1\\d|[1-9])?\\d)(\\.|\\b)){4}"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
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