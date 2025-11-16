resource "azurerm_sentinel_alert_rule_scheduled" "enable_microsoft_dynamic_data_exchange" {
  name                       = "enable_microsoft_dynamic_data_exchange"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Enable Microsoft Dynamic Data Exchange"
  description                = "Enable Dynamic Data Exchange protocol (DDE) in all supported editions of Microsoft Word or Excel."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey endswith "\\Excel\\Security\\DisableDDEServerLaunch" or RegistryKey endswith "\\Excel\\Security\\DisableDDEServerLookup")) or ((RegistryValueData in~ ("DWORD (0x00000001)", "DWORD (0x00000002)")) and RegistryKey endswith "\\Word\\Security\\AllowDDE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1559"]
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