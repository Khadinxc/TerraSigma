resource "azurerm_sentinel_alert_rule_scheduled" "internet_explorer_disablefirstruncustomize_enabled" {
  name                       = "internet_explorer_disablefirstruncustomize_enabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Internet Explorer DisableFirstRunCustomize Enabled"
  description                = "Detects changes to the Internet Explorer \"DisableFirstRunCustomize\" value, which prevents Internet Explorer from running the first run wizard the first time a user starts the browser after installing Internet Explorer or Windows. - As this is controlled by group policy as well as user settings. Some false positives may occur."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData in~ ("DWORD (0x00000001)", "DWORD (0x00000002)")) and RegistryKey endswith "\\Microsoft\\Internet Explorer\\Main\\DisableFirstRunCustomize") and (not((InitiatingProcessFolderPath in~ ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\ie4uinit.exe")))) and (not(((RegistryValueData contains "DWORD (0x00000001)" and (InitiatingProcessFolderPath contains "\\Temp\\" and InitiatingProcessFolderPath contains "\\.cr\\avira_")) or (RegistryValueData contains "DWORD (0x00000001)" and (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Foxit Software\\Foxit PDF Reader\\FoxitPDFReader.exe", "C:\\Program Files\\Foxit Software\\Foxit PDF Reader\\FoxitPDFReader.exe"))))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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