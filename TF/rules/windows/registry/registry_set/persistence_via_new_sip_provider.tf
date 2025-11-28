resource "azurerm_sentinel_alert_rule_scheduled" "persistence_via_new_sip_provider" {
  name                       = "persistence_via_new_sip_provider"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Persistence Via New SIP Provider"
  description                = "Detects when an attacker register a new SIP provider for persistence and defense evasion - Legitimate SIP being registered by the OS or different software."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey contains "\\Dll" or RegistryKey contains "\\$DLL") and (RegistryKey endswith "\\SOFTWARE\\Microsoft\\Cryptography\\Providers*" or RegistryKey contains "\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType" or RegistryKey endswith "\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers*" or RegistryKey contains "\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType")) and (not(((RegistryValueData in~ ("WINTRUST.DLL", "mso.dll")) or (RegistryValueData =~ "C:\\Windows\\System32\\PsfSip.dll" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\poqexec.exe" and RegistryKey contains "\\CryptSIPDll"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1553"]
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