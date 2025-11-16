resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_scrobj_dll_com_hijacking" {
  name                       = "potential_persistence_via_scrobj_dll_com_hijacking"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Scrobj.dll COM Hijacking"
  description                = "Detect use of scrobj.dll as this DLL looks for the ScriptletURL key to get the location of the script to execute - Legitimate use of the dll."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "C:\\WINDOWS\\system32\\scrobj.dll" and RegistryKey endswith "InprocServer32\\(Default)"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1546"]
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