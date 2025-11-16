resource "azurerm_sentinel_alert_rule_scheduled" "disable_macro_runtime_scan_scope" {
  name                       = "disable_macro_runtime_scan_scope"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Macro Runtime Scan Scope"
  description                = "Detects tampering with the MacroRuntimeScanScope registry key to disable runtime scanning of enabled macros"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey endswith "\\SOFTWARE*" and RegistryKey endswith "\\Microsoft\\Office*" and RegistryKey contains "\\Common\\Security") and RegistryKey endswith "\\MacroRuntimeScanScope"
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