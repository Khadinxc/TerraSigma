resource "azurerm_sentinel_alert_rule_scheduled" "enable_remote_connection_between_anonymous_computer_allowanonymouscallback" {
  name                       = "enable_remote_connection_between_anonymous_computer_allowanonymouscallback"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback"
  description                = "Detects enabling of the \"AllowAnonymousCallback\" registry value, which allows a remote connection between computers that do not have a trust relationship. - Administrative activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey contains "\\Microsoft\\WBEM\\CIMOM\\AllowAnonymousCallback"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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