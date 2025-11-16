resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_autodialdll" {
  name                       = "potential_persistence_via_autodialdll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via AutodialDLL"
  description                = "Detects change the the \"AutodialDLL\" key which could be used as a persistence method to load custom DLL via the \"ws2_32\" library - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Services\\WinSock2\\Parameters\\AutodialDLL"
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
  }
}