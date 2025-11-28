resource "azurerm_sentinel_alert_rule_scheduled" "registry_hide_function_from_user" {
  name                       = "registry_hide_function_from_user"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Hide Function from User"
  description                = "Detects registry modifications that hide internal tools or functions from the user (malware like Agent Tesla, Hermetic Wiper uses this technique) - Legitimate admin script"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowInfoTip" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowCompColor")) or (RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideClock" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAHealth" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCANetwork" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAPower" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAVolume"))
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