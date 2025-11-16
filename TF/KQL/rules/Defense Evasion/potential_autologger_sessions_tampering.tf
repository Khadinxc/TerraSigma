resource "azurerm_sentinel_alert_rule_scheduled" "potential_autologger_sessions_tampering" {
  name                       = "potential_autologger_sessions_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential AutoLogger Sessions Tampering"
  description                = "Detects tampering with autologger trace sessions which is a technique used by attackers to disable logging"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\System\\CurrentControlSet\\Control\\WMI\\Autologger*" and (RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey contains "\\EventLog-" or RegistryKey contains "\\Defender") and (RegistryKey endswith "\\Enable" or RegistryKey endswith "\\Start"))) and (not(((InitiatingProcessFolderPath endswith "\\MsMpEng.exe" and (InitiatingProcessFolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Windows Defender\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Windows Defender\\") and (RegistryKey endswith "\\DefenderApiLogger*" or RegistryKey endswith "\\DefenderAuditLogger*")) or InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\wevtutil.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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