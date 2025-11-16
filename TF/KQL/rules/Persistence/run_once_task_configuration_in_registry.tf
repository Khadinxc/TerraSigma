resource "azurerm_sentinel_alert_rule_scheduled" "run_once_task_configuration_in_registry" {
  name                       = "run_once_task_configuration_in_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Run Once Task Configuration in Registry"
  description                = "Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup - Legitimate modification of the registry key by legitimate program"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\Microsoft\\Active Setup\\Installed Components" and RegistryKey endswith "\\StubPath") and (not(((RegistryValueData contains "C:\\Program Files\\Google\\Chrome\\Application\\" and RegistryValueData contains "\\Installer\\chrmstp.exe\" --configure-user-settings --verbose-logging --system-level") or ((RegistryValueData contains "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\" or RegistryValueData contains "C:\\Program Files\\Microsoft\\Edge\\Application\\") and RegistryValueData endswith "\\Installer\\setup.exe\" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable"))))
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