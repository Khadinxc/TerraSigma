resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_app_paths_default_property" {
  name                       = "potential_persistence_via_app_paths_default_property"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via App Paths Default Property"
  description                = "Detects changes to the \"Default\" property for keys located in the \\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ registry. Which might be used as a method of persistence The entries found under App Paths are used primarily for the following purposes. First, to map an application's executable file name to that file's fully qualified path. Second, to prepend information to the PATH environment variable on a per-application, per-process basis. - Legitimate applications registering their binary from on of the suspicious locations mentioned above (tune it)"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "\\Users\\Public" or RegistryValueData contains "\\AppData\\Local\\Temp\\" or RegistryValueData contains "\\Windows\\Temp\\" or RegistryValueData contains "\\Desktop\\" or RegistryValueData contains "\\Downloads\\" or RegistryValueData contains "%temp%" or RegistryValueData contains "%tmp%" or RegistryValueData contains "iex" or RegistryValueData contains "Invoke-" or RegistryValueData contains "rundll32" or RegistryValueData contains "regsvr32" or RegistryValueData contains "mshta" or RegistryValueData contains "cscript" or RegistryValueData contains "wscript" or RegistryValueData contains ".bat" or RegistryValueData contains ".hta" or RegistryValueData contains ".dll" or RegistryValueData contains ".ps1") and RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths" and (RegistryKey endswith "(Default)" or RegistryKey endswith "Path")
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