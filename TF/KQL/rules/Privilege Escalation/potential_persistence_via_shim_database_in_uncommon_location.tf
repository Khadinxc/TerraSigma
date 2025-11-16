resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_shim_database_in_uncommon_location" {
  name                       = "potential_persistence_via_shim_database_in_uncommon_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Shim Database In Uncommon Location"
  description                = "Detects the installation of a new shim database where the file is located in a non-default location"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB*" and RegistryKey contains "\\DatabasePath") and (not(RegistryValueData contains ":\\Windows\\AppPatch\\Custom"))
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