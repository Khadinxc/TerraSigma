resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_new_amsi_providers_registry" {
  name                       = "potential_persistence_via_new_amsi_providers_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via New AMSI Providers - Registry"
  description                = "Detects when an attacker registers a new AMSI provider in order to achieve persistence - Legitimate security products adding their own AMSI providers. Filter these according to your environment"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (ActionType =~ "RegistryKeyCreated" and (RegistryKey endswith "\\SOFTWARE\\Microsoft\\AMSI\\Providers*" or RegistryKey endswith "\\SOFTWARE\\WOW6432Node\\Microsoft\\AMSI\\Providers*")) and (not((InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\")))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}