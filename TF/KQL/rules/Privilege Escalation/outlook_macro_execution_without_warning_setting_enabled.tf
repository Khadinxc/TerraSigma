resource "azurerm_sentinel_alert_rule_scheduled" "outlook_macro_execution_without_warning_setting_enabled" {
  name                       = "outlook_macro_execution_without_warning_setting_enabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Outlook Macro Execution Without Warning Setting Enabled"
  description                = "Detects the modification of Outlook security setting to allow unprompted execution of macros. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData contains "0x00000001" and RegistryKey endswith "\\Outlook\\Security\\Level"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "CommandAndControl"]
  techniques                 = ["T1137", "T1008", "T1546"]
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