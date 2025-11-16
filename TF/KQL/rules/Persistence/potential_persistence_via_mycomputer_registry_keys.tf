resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_mycomputer_registry_keys" {
  name                       = "potential_persistence_via_mycomputer_registry_keys"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via MyComputer Registry Keys"
  description                = "Detects modification to the \"Default\" value of the \"MyComputer\" key and subkeys to point to a custom binary that will be launched whenever the associated action is executed (see reference section for example) - Unlikely but if you experience FPs add specific processes and locations you would like to monitor for"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer" and RegistryKey endswith "(Default)"
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