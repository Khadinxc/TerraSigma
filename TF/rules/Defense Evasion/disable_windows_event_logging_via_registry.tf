resource "azurerm_sentinel_alert_rule_scheduled" "disable_windows_event_logging_via_registry" {
  name                       = "disable_windows_event_logging_via_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Windows Event Logging Via Registry"
  description                = "Detects tampering with the \"Enabled\" registry key in order to disable Windows logging of a Windows event channel - Rare falsepositives may occur from legitimate administrators disabling specific event log for troubleshooting"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels*" and RegistryKey endswith "\\Enabled") and (not(((InitiatingProcessFolderPath endswith "\\TiWorker.exe" and InitiatingProcessFolderPath startswith "C:\\Windows\\winsxs\\") or (InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\svchost.exe" and (RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-FileInfoMinifilter" or RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-ASN1*" or RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Kernel-AppCompat*" or RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Runtime\\Error*" or RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-CAPI2/Operational*")) or (InitiatingProcessFolderPath =~ "C:\\Windows\\servicing\\TrustedInstaller.exe" and RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Compat-Appraiser") or InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\wevtutil.exe"))) and (not((InitiatingProcessFolderPath =~ "" or isnull(InitiatingProcessFolderPath))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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