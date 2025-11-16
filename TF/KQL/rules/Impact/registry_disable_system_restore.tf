resource "azurerm_sentinel_alert_rule_scheduled" "registry_disable_system_restore" {
  name                       = "registry_disable_system_restore"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Disable System Restore"
  description                = "Detects the modification of the registry to disable a system restore on the computer"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey contains "\\Policies\\Microsoft\\Windows NT\\SystemRestore" or RegistryKey contains "\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore") and (RegistryKey endswith "DisableConfig" or RegistryKey endswith "DisableSR")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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