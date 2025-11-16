resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_dllpathoverride" {
  name                       = "potential_persistence_via_dllpathoverride"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via DLLPathOverride"
  description                = "Detects when an attacker adds a new \"DLLPathOverride\" value to the \"Natural Language\" key in order to achieve persistence which will get invoked by \"SearchIndexer.exe\" process"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\SYSTEM\\CurrentControlSet\\Control\\ContentIndex\\Language*" and (RegistryKey contains "\\StemmerDLLPathOverride" or RegistryKey contains "\\WBDLLPathOverride" or RegistryKey contains "\\StemmerClass" or RegistryKey contains "\\WBreakerClass")
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