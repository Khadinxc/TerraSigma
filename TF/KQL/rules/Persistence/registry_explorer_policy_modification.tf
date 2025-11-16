resource "azurerm_sentinel_alert_rule_scheduled" "registry_explorer_policy_modification" {
  name                       = "registry_explorer_policy_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Explorer Policy Modification"
  description                = "Detects registry modifications that disable internal tools or functions in explorer (malware like Agent Tesla uses this technique) - Legitimate admin script"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoLogOff" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDesktop" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFind" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoControlPanel" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFileMenu" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoClose" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoSetTaskbar" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoPropertiesMyDocuments" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoTrayContextMenu")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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