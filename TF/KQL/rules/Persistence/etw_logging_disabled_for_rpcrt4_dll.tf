resource "azurerm_sentinel_alert_rule_scheduled" "etw_logging_disabled_for_rpcrt4_dll" {
  name                       = "etw_logging_disabled_for_rpcrt4_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ETW Logging Disabled For rpcrt4.dll"
  description                = "Detects changes to the \"ExtErrorInformation\" key in order to disable ETW logging for rpcrt4.dll"
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData in~ ("DWORD (0x00000000)", "DWORD (0x00000002)")) and RegistryKey endswith "\\Microsoft\\Windows NT\\Rpc\\ExtErrorInformation"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112", "T1562"]
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