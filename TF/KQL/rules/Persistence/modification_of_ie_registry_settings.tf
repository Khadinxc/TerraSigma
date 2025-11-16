resource "azurerm_sentinel_alert_rule_scheduled" "modification_of_ie_registry_settings" {
  name                       = "modification_of_ie_registry_settings"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Modification of IE Registry Settings"
  description                = "Detects modification of the registry settings used for Internet Explorer and other Windows components that use these settings. An attacker can abuse this registry key to add a domain to the trusted sites Zone or insert JavaScript for persistence"
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" and (not((RegistryValueData =~ "Binary Data" or RegistryValueData startswith "DWORD" or isnull(RegistryValueData) or (RegistryValueData in~ ("Cookie:", "Visited:", "(Empty)")) or (RegistryKey contains "\\Cache" or RegistryKey contains "\\ZoneMap" or RegistryKey contains "\\WpadDecision")))) and (not(RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Accepted Documents"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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