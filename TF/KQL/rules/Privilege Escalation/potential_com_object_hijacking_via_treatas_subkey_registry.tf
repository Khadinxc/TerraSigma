resource "azurerm_sentinel_alert_rule_scheduled" "potential_com_object_hijacking_via_treatas_subkey_registry" {
  name                       = "potential_com_object_hijacking_via_treatas_subkey_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential COM Object Hijacking Via TreatAs Subkey - Registry"
  description                = "Detects COM object hijacking via TreatAs subkey - Maybe some system utilities in rare cases use linking keys for backward compatibility"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (ActionType =~ "RegistryKeyCreated" and (RegistryKey endswith "HKU*" and RegistryKey endswith "Classes\\CLSID*" and RegistryKey contains "\\TreatAs")) and (not(InitiatingProcessFolderPath =~ "C:\\WINDOWS\\system32\\svchost.exe"))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}