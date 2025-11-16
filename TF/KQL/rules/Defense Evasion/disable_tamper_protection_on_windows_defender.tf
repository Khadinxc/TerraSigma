resource "azurerm_sentinel_alert_rule_scheduled" "disable_tamper_protection_on_windows_defender" {
  name                       = "disable_tamper_protection_on_windows_defender"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Tamper Protection on Windows Defender"
  description                = "Detects disabling Windows Defender Tamper Protection"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey contains "\\Microsoft\\Windows Defender\\Features\\TamperProtection") and (not(((InitiatingProcessFolderPath endswith "\\MsMpEng.exe" and InitiatingProcessFolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\") or InitiatingProcessFolderPath =~ "C:\\Program Files\\Windows Defender\\MsMpEng.exe")))
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