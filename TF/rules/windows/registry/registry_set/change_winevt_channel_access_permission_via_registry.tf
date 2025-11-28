resource "azurerm_sentinel_alert_rule_scheduled" "change_winevt_channel_access_permission_via_registry" {
  name                       = "change_winevt_channel_access_permission_via_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Change Winevt Channel Access Permission Via Registry"
  description                = "Detects tampering with the \"ChannelAccess\" registry key in order to change access to Windows event channel."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData contains "(A;;0x1;;;LA)" or RegistryValueData contains "(A;;0x1;;;SY)" or RegistryValueData contains "(A;;0x5;;;BA)") and RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels*" and RegistryKey endswith "\\ChannelAccess") and (not(((InitiatingProcessFolderPath endswith "\\TiWorker.exe" and InitiatingProcessFolderPath startswith "C:\\Windows\\WinSxS\\") or InitiatingProcessFolderPath =~ "C:\\Windows\\servicing\\TrustedInstaller.exe")))
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