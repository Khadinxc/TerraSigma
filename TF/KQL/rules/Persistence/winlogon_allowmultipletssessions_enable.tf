resource "azurerm_sentinel_alert_rule_scheduled" "winlogon_allowmultipletssessions_enable" {
  name                       = "winlogon_allowmultipletssessions_enable"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Winlogon AllowMultipleTSSessions Enable"
  description                = "Detects when the 'AllowMultipleTSSessions' value is enabled. Which allows for multiple Remote Desktop connection sessions to be opened at once. This is often used by attacker as a way to connect to an RDP session without disconnecting the other users - Legitimate use of the multi session functionality"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData endswith "DWORD (0x00000001)" and RegistryKey endswith "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllowMultipleTSSessions"
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