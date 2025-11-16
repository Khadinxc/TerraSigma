resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_keyboard_layout_load" {
  name                       = "suspicious_keyboard_layout_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Keyboard Layout Load"
  description                = "Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only - Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "00000429" or RegistryValueData contains "00050429" or RegistryValueData contains "0000042a") and (RegistryKey endswith "\\Keyboard Layout\\Preload*" or RegistryKey endswith "\\Keyboard Layout\\Substitutes*")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1588"]
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