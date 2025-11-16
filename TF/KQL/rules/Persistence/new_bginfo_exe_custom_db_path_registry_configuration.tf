resource "azurerm_sentinel_alert_rule_scheduled" "new_bginfo_exe_custom_db_path_registry_configuration" {
  name                       = "new_bginfo_exe_custom_db_path_registry_configuration"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New BgInfo.EXE Custom DB Path Registry Configuration"
  description                = "Detects setting of a new registry database value related to BgInfo configuration. Attackers can for example set this value to save the results of the commands executed by BgInfo in order to exfiltrate information. - Legitimate use of external DB to save the results"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Software\\Winternals\\BGInfo\\Database"
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
  }
}