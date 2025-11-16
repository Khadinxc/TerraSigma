resource "azurerm_sentinel_alert_rule_scheduled" "potential_werfault_reflectdebugger_registry_value_abuse" {
  name                       = "potential_werfault_reflectdebugger_registry_value_abuse"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential WerFault ReflectDebugger Registry Value Abuse"
  description                = "Detects potential WerFault \"ReflectDebugger\" registry value abuse for persistence."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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