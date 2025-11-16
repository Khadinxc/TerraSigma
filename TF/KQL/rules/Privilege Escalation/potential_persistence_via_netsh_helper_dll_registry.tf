resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_netsh_helper_dll_registry" {
  name                       = "potential_persistence_via_netsh_helper_dll_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Netsh Helper DLL - Registry"
  description                = "Detects changes to the Netsh registry key to add a new DLL value. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper - Legitimate helper added by different programs and the OS"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains ".dll" and RegistryKey contains "\\SOFTWARE\\Microsoft\\NetSh") and (not(((RegistryValueData in~ ("ipmontr.dll", "iasmontr.dll", "ippromon.dll")) and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\poqexec.exe")))
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}