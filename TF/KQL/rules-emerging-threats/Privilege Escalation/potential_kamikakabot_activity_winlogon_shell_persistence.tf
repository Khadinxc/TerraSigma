resource "azurerm_sentinel_alert_rule_scheduled" "potential_kamikakabot_activity_winlogon_shell_persistence" {
  name                       = "potential_kamikakabot_activity_winlogon_shell_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential KamiKakaBot Activity - Winlogon Shell Persistence"
  description                = "Detects changes to the \"Winlogon\" registry key where a process will set the value of the \"Shell\" to a value that was observed being used by KamiKakaBot samples in order to achieve persistence. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "-nop -w h" and RegistryValueData contains "$env" and RegistryValueData contains "explorer.exe" and RegistryValueData contains "Start-Process") and RegistryKey endswith "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
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