resource "azurerm_sentinel_alert_rule_scheduled" "dll_load_via_lsass" {
  name                       = "dll_load_via_lsass"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DLL Load via LSASS"
  description                = "Detects a method to load DLL via LSASS process using an undocumented Registry key"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt" or RegistryKey contains "\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt") and (not(((RegistryValueData in~ ("%%systemroot%%\\system32\\ntdsa.dll", "%%systemroot%%\\system32\\lsadb.dll")) and InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\lsass.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}