resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_mpnotify" {
  name                       = "potential_persistence_via_mpnotify"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Mpnotify"
  description                = "Detects when an attacker register a new SIP provider for persistence and defense evasion - Might trigger if a legitimate new SIP provider is registered. But this is not a common occurrence in an environment and should be investigated either way"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\mpnotify"
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