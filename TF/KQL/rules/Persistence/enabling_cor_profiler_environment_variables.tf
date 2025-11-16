resource "azurerm_sentinel_alert_rule_scheduled" "enabling_cor_profiler_environment_variables" {
  name                       = "enabling_cor_profiler_environment_variables"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Enabling COR Profiler Environment Variables"
  description                = "Detects .NET Framework CLR and .NET Core CLR \"cor_enable_profiling\" and \"cor_profiler\" variables being set and configured."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\COR_ENABLE_PROFILING" or RegistryKey endswith "\\COR_PROFILER" or RegistryKey endswith "\\CORECLR_ENABLE_PROFILING") or RegistryKey contains "\\CORECLR_PROFILER_PATH"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1574"]
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