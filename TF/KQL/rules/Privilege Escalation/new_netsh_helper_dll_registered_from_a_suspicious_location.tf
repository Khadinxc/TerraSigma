resource "azurerm_sentinel_alert_rule_scheduled" "new_netsh_helper_dll_registered_from_a_suspicious_location" {
  name                       = "new_netsh_helper_dll_registered_from_a_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Netsh Helper DLL Registered From A Suspicious Location"
  description                = "Detects changes to the Netsh registry key to add a new DLL value that is located on a suspicious location. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\SOFTWARE\\Microsoft\\NetSh" and ((RegistryValueData contains ":\\Perflogs\\" or RegistryValueData contains ":\\Users\\Public\\" or RegistryValueData contains ":\\Windows\\Temp\\" or RegistryValueData contains "\\AppData\\Local\\Temp\\" or RegistryValueData contains "\\Temporary Internet") or ((RegistryValueData contains ":\\Users\\" and RegistryValueData contains "\\Favorites\\") or (RegistryValueData contains ":\\Users\\" and RegistryValueData contains "\\Favourites\\") or (RegistryValueData contains ":\\Users\\" and RegistryValueData contains "\\Contacts\\") or (RegistryValueData contains ":\\Users\\" and RegistryValueData contains "\\Pictures\\")))
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