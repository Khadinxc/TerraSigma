resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_appcompat_registerapprestart_layer" {
  name                       = "potential_persistence_via_appcompat_registerapprestart_layer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via AppCompat RegisterAppRestart Layer"
  description                = "Detects the setting of the REGISTERAPPRESTART compatibility layer on an application. This compatibility layer allows an application to register for restart using the \"RegisterApplicationRestart\" API. This can be potentially abused as a persistence mechanism. - Legitimate applications making use of this feature for compatibility reasons"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData contains "REGISTERAPPRESTART" and RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers*"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1546"]
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