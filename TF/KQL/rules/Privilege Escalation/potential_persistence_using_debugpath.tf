resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_using_debugpath" {
  name                       = "potential_persistence_using_debugpath"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Using DebugPath"
  description                = "Detects potential persistence using Appx DebugPath"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "Classes\\ActivatableClasses\\Package\\Microsoft." and RegistryKey endswith "\\DebugPath") or (RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug\\Microsoft." and RegistryKey endswith "\\(Default)")
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
  }
}