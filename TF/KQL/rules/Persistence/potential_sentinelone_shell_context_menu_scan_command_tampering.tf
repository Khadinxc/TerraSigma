resource "azurerm_sentinel_alert_rule_scheduled" "potential_sentinelone_shell_context_menu_scan_command_tampering" {
  name                       = "potential_sentinelone_shell_context_menu_scan_command_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential SentinelOne Shell Context Menu Scan Command Tampering"
  description                = "Detects potentially suspicious changes to the SentinelOne context menu scan command by a process other than SentinelOne."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\shell\\SentinelOneScan\\command*" and (not(((InitiatingProcessFolderPath endswith "C:\\Program Files\\SentinelOne\\" or InitiatingProcessFolderPath endswith "C:\\Program Files (x86)\\SentinelOne\\") or (RegistryValueData contains "\\SentinelScanFromContextMenu.exe" and (RegistryValueData startswith "C:\\Program Files\\SentinelOne\\Sentinel Agent" or RegistryValueData startswith "C:\\Program Files (x86)\\SentinelOne\\Sentinel Agent")))))
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