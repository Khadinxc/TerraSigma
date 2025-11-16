resource "azurerm_sentinel_alert_rule_scheduled" "oilrig_apt_registry_persistence" {
  name                       = "oilrig_apt_registry_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OilRig APT Registry Persistence"
  description                = "Detects OilRig registry persistence as reported by Nyotron in their March 2018 report - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence", "DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1053", "T1543", "T1112", "T1071"]
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