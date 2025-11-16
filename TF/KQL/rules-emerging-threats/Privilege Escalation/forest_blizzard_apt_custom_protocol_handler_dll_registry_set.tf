resource "azurerm_sentinel_alert_rule_scheduled" "forest_blizzard_apt_custom_protocol_handler_dll_registry_set" {
  name                       = "forest_blizzard_apt_custom_protocol_handler_dll_registry_set"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Forest Blizzard APT - Custom Protocol Handler DLL Registry Set"
  description                = "Detects the setting of the DLL that handles the custom protocol handler. Seen being created by Forest Blizzard APT as reported by MSFT. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData endswith ".dll" and RegistryKey contains "\\CLSID\\{026CC6D7-34B2-33D5-B551-CA31EB6CE345}\\Server"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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