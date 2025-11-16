resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_chm_helper_dll" {
  name                       = "potential_persistence_via_chm_helper_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via CHM Helper DLL"
  description                = "Detects when an attacker modifies the registry key \"HtmlHelp Author\" to achieve persistence"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Software\\Microsoft\\HtmlHelp Author\\Location" or RegistryKey contains "\\Software\\WOW6432Node\\Microsoft\\HtmlHelp Author\\Location"
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