resource "azurerm_sentinel_alert_rule_scheduled" "wow6432node_windows_nt_currentversion_autorun_keys_modification" {
  name                       = "wow6432node_windows_nt_currentversion_autorun_keys_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wow6432Node Windows NT CurrentVersion Autorun Keys Modification"
  description                = "Detects modification of autostart extensibility point (ASEP) in registry. - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason - Legitimate administrator sets up autorun keys for legitimate reason"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey contains "\\Windows\\Appinit_Dlls" or RegistryKey contains "\\Image File Execution Options" or RegistryKey contains "\\Drivers32") and RegistryKey contains "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion") and (not((RegistryValueData =~ "(Empty)" or RegistryValueData endswith "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" or isnull(RegistryValueData))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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