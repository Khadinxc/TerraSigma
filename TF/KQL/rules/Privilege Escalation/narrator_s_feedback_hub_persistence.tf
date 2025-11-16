resource "azurerm_sentinel_alert_rule_scheduled" "narrator_s_feedback_hub_persistence" {
  name                       = "narrator_s_feedback_hub_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Narrator's Feedback-Hub Persistence"
  description                = "Detects abusing Windows 10 Narrator's Feedback-Hub"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (ActionType =~ "DeleteValue" and RegistryKey endswith "\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute") or RegistryKey endswith "\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\(Default)"
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
  }
}