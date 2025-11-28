resource "azurerm_sentinel_alert_rule_scheduled" "potential_raspberry_robin_registry_set_internet_settings_zonemap" {
  name                       = "potential_raspberry_robin_registry_set_internet_settings_zonemap"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Raspberry Robin Registry Set Internet Settings ZoneMap"
  description                = "Detects registry modifications related to the proxy configuration of the system, potentially associated with the Raspberry Robin malware, as seen in campaigns running in Q1 2024. Raspberry Robin may alter proxy settings to circumvent security measures, ensuring unhindered connection with Command and Control servers for maintaining control over compromised systems if there are any proxy settings that are blocking connections."
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where (((InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" or InitiatingProcessFolderPath contains "\\Downloads\\" or InitiatingProcessFolderPath contains "\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\Windows\\Temp\\") or InitiatingProcessFolderPath endswith "\\control.exe") and RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap*") and ((RegistryValueData contains "DWORD (0x00000000)" and RegistryKey endswith "\\AutoDetect") or (RegistryValueData contains "DWORD (0x00000001)" and (RegistryKey endswith "\\IntranetName" or RegistryKey endswith "\\ProxyByPass" or RegistryKey endswith "\\UNCAsIntranet")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}