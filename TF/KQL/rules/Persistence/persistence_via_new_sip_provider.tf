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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}