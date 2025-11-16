resource "azurerm_sentinel_alert_rule_scheduled" "kapeka_backdoor_configuration_persistence" {
  name                       = "kapeka_backdoor_configuration_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Kapeka Backdoor Configuration Persistence"
  description                = "Detects registry set activity of a value called \"Seed\" stored in the \"\\Cryptography\\Providers\\\" registry key. The Kapeka backdoor leverages this location to register a new SIP provider for backdoor configuration persistence."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\{" and RegistryKey endswith "\\Seed") and (not(RegistryValueData contains "(Empty)"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1553"]
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