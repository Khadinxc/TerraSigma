resource "azurerm_sentinel_alert_rule_scheduled" "new_bginfo_exe_custom_vbscript_registry_configuration" {
  name                       = "new_bginfo_exe_custom_vbscript_registry_configuration"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New BgInfo.EXE Custom VBScript Registry Configuration"
  description                = "Detects setting of a new registry value related to BgInfo configuration, which can be abused to execute custom VBScript via \"BgInfo.exe\" - Legitimate VBScript"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData startswith "4" and RegistryKey endswith "\\Software\\Winternals\\BGInfo\\UserFields*"
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