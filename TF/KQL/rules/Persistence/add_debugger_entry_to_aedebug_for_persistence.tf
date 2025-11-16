resource "azurerm_sentinel_alert_rule_scheduled" "add_debugger_entry_to_aedebug_for_persistence" {
  name                       = "add_debugger_entry_to_aedebug_for_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Add Debugger Entry To AeDebug For Persistence"
  description                = "Detects when an attacker adds a new \"Debugger\" value to the \"AeDebug\" key in order to achieve persistence which will get invoked when an application crashes - Legitimate use of the key to setup a debugger. Which is often the case on developers machines"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData endswith ".dll" and RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\Debugger") and (not(RegistryValueData =~ "\"C:\\WINDOWS\\system32\\vsjitdebugger.exe\" -p %ld -e %ld -j 0x%p"))
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}