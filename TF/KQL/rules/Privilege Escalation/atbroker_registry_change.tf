resource "azurerm_sentinel_alert_rule_scheduled" "atbroker_registry_change" {
  name                       = "atbroker_registry_change"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Atbroker Registry Change"
  description                = "Detects creation/modification of Assistive Technology applications and persistence with usage of 'at' - Creation of non-default, legitimate at usage"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs" or RegistryKey contains "Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration") and (not(((RegistryValueData =~ "(Empty)" and InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\atbroker.exe" and RegistryKey contains "\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration") or (InitiatingProcessFolderPath startswith "C:\\Windows\\Installer\\MSI" and RegistryKey contains "Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion", "Persistence"]
  techniques                 = ["T1218", "T1547"]
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