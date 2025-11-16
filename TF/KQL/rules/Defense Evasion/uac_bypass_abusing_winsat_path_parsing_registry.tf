resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_abusing_winsat_path_parsing_registry" {
  name                       = "uac_bypass_abusing_winsat_path_parsing_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Abusing Winsat Path Parsing - Registry"
  description                = "Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData endswith "\\appdata\\local\\temp\\system32\\winsat.exe" and RegistryValueData startswith "c:\\users\\" and RegistryKey contains "\\Root\\InventoryApplicationFile\\winsat.exe|" and RegistryKey endswith "\\LowerCaseLongPath"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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