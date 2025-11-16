resource "azurerm_sentinel_alert_rule_scheduled" "modify_user_shell_folders_startup_value" {
  name                       = "modify_user_shell_folders_startup_value"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Modify User Shell Folders Startup Value"
  description                = "Detect modification of the startup key to a path where a payload could be stored to be launched during startup"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" and RegistryKey endswith "Startup"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
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
  }
}