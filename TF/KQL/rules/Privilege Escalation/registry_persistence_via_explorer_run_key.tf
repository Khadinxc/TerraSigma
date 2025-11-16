resource "azurerm_sentinel_alert_rule_scheduled" "registry_persistence_via_explorer_run_key" {
  name                       = "registry_persistence_via_explorer_run_key"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Persistence via Explorer Run Key"
  description                = "Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains ":\\$Recycle.bin\\" or RegistryValueData contains ":\\ProgramData\\" or RegistryValueData contains ":\\Temp\\" or RegistryValueData contains ":\\Users\\Default\\" or RegistryValueData contains ":\\Users\\Public\\" or RegistryValueData contains ":\\Windows\\Temp\\" or RegistryValueData contains "\\AppData\\Local\\Temp\\") and RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
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