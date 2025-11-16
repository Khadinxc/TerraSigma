resource "azurerm_sentinel_alert_rule_scheduled" "scripted_diagnostics_turn_off_check_enabled_registry" {
  name                       = "scripted_diagnostics_turn_off_check_enabled_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scripted Diagnostics Turn Off Check Enabled - Registry"
  description                = "Detects enabling TurnOffCheck which can be used to bypass defense of MSDT Follina vulnerability - Administrator actions"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey endswith "\\Policies\\Microsoft\\Windows\\ScriptedDiagnostics\\TurnOffCheck"
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