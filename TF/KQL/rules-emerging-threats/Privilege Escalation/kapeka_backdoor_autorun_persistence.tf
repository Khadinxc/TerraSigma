resource "azurerm_sentinel_alert_rule_scheduled" "kapeka_backdoor_autorun_persistence" {
  name                       = "kapeka_backdoor_autorun_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Kapeka Backdoor Autorun Persistence"
  description                = "Detects the setting of a new value in the Autorun key that is used by the Kapeka backdoor for persistence."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains ":\\WINDOWS\\system32\\rundll32.exe" and RegistryValueData contains ".wll" and RegistryValueData contains "#1") and RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" and (RegistryKey endswith "\\Sens Api" or RegistryKey endswith "\\OneDrive")
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