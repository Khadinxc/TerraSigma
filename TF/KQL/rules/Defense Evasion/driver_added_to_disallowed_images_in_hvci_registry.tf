resource "azurerm_sentinel_alert_rule_scheduled" "driver_added_to_disallowed_images_in_hvci_registry" {
  name                       = "driver_added_to_disallowed_images_in_hvci_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Driver Added To Disallowed Images In HVCI - Registry"
  description                = "Detects changes to the \"HVCIDisallowedImages\" registry value to potentially add a driver to the list, in order to prevent it from loading. - Legitimate usage of this key would also trigger this. Investigate the driver being added and make sure its intended"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Control\\CI*" and RegistryKey contains "\\HVCIDisallowedImages"
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
  }
}