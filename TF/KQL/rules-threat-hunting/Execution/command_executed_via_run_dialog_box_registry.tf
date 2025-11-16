resource "azurerm_sentinel_alert_rule_scheduled" "command_executed_via_run_dialog_box_registry" {
  name                       = "command_executed_via_run_dialog_box_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Command Executed Via Run Dialog Box - Registry"
  description                = "Detects execution of commands via the run dialog box on Windows by checking values of the \"RunMRU\" registry key. This technique was seen being abused by threat actors to deceive users into pasting and executing malicious commands, often disguised as CAPTCHA verification steps. - Likely"
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" and (not(RegistryKey endswith "\\MRUList")) and (not(((RegistryValueData in~ ("%appdata%\\1", "%localappdata%\\1", "%public%\\1", "%temp%\\1", "calc\\1", "dxdiag\\1", "explorer\\1", "gpedit.msc\\1", "mmc\\1", "notepad\\1", "regedit\\1", "services.msc\\1", "winver\\1")) or RegistryValueData contains "ping")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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