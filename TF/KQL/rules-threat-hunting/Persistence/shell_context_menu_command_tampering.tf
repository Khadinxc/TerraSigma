resource "azurerm_sentinel_alert_rule_scheduled" "shell_context_menu_command_tampering" {
  name                       = "shell_context_menu_command_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shell Context Menu Command Tampering"
  description                = "Detects changes to shell context menu commands. Use this rule to hunt for potential anomalies and suspicious shell commands. - Likely from new software installation suggesting to add context menu items. Such as \"PowerShell\", \"Everything\", \"Git\", etc."
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Software\\Classes*" and RegistryKey endswith "\\shell*" and RegistryKey endswith "\\command*"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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