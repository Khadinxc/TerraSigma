resource "azurerm_sentinel_alert_rule_scheduled" "blue_mockingbird_registry" {
  name                       = "blue_mockingbird_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Blue Mockingbird - Registry"
  description                = "Attempts to detect system changes made by Blue Mockingbird"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\CurrentControlSet\\Services\\wercplsupport\\Parameters\\ServiceDll"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution", "Persistence"]
  techniques                 = ["T1112", "T1047"]
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