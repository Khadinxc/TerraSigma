resource "azurerm_sentinel_alert_rule_scheduled" "new_timeproviders_registered_with_uncommon_dll_name" {
  name                       = "new_timeproviders_registered_with_uncommon_dll_name"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New TimeProviders Registered With Uncommon DLL Name"
  description                = "Detects processes setting a new DLL in DllName in under HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProvider. Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\Services\\W32Time\\TimeProviders" and RegistryKey endswith "\\DllName") and (not((RegistryValueData in~ ("%SystemRoot%\\System32\\vmictimeprovider.dll", "%systemroot%\\system32\\w32time.dll", "C:\\Windows\\SYSTEM32\\w32time.DLL"))))
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}