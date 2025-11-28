resource "azurerm_sentinel_alert_rule_scheduled" "service_binary_in_suspicious_folder" {
  name                       = "service_binary_in_suspicious_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Service Binary in Suspicious Folder"
  description                = "Detect the creation of a service with a service binary located in a suspicious directory"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (((RegistryValueData contains "\\Users\\Public\\" or RegistryValueData contains "\\Perflogs\\" or RegistryValueData contains "\\ADMIN$\\" or RegistryValueData contains "\\Temp\\") and RegistryKey endswith "\\ImagePath" and RegistryKey =~ "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001\\Services*") or ((RegistryValueData in~ ("DWORD (0x00000000)", "DWORD (0x00000001)", "DWORD (0x00000002)")) and (InitiatingProcessFolderPath contains "\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\Perflogs\\" or InitiatingProcessFolderPath contains "\\ADMIN$\\" or InitiatingProcessFolderPath contains "\\Temp\\") and RegistryKey endswith "\\Start" and RegistryKey =~ "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001\\Services*")) and (not(((InitiatingProcessFolderPath contains "\\Common Files\\" and InitiatingProcessFolderPath contains "\\Temp\\") or (RegistryValueData endswith "\\AppData\\Local\\Temp\\MBAMInstallerService.exe\"" and InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\services.exe" and RegistryKey endswith "\\CurrentControlSet\\Services\\MBAMInstallerService\\ImagePath"))))
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