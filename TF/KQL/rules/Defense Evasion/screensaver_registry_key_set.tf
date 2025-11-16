resource "azurerm_sentinel_alert_rule_scheduled" "screensaver_registry_key_set" {
  name                       = "screensaver_registry_key_set"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ScreenSaver Registry Key Set"
  description                = "Detects registry key established after masqueraded .scr file execution using Rundll32 through desk.cpl - Legitimate use of screen saver"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where InitiatingProcessFolderPath endswith "\\rundll32.exe" and (RegistryValueData endswith ".scr" and RegistryKey contains "\\Control Panel\\Desktop\\SCRNSAVE.EXE") and (not((RegistryValueData contains "C:\\Windows\\System32\\" or RegistryValueData contains "C:\\Windows\\SysWOW64\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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