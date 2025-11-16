resource "azurerm_sentinel_alert_rule_scheduled" "persistence_via_hhctrl_ocx" {
  name                       = "persistence_via_hhctrl_ocx"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Persistence Via Hhctrl.ocx"
  description                = "Detects when an attacker modifies the registry value of the \"hhctrl\" to point to a custom binary - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\CLSID\\{52A2AAAE-085D-4187-97EA-8C30DB990436}\\InprocServer32\\(Default)" and (not(RegistryValueData =~ "C:\\Windows\\System32\\hhctrl.ocx"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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