resource "azurerm_sentinel_alert_rule_scheduled" "renamed_autohotkey_exe_execution" {
  name                       = "renamed_autohotkey_exe_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed AutoHotkey.EXE Execution"
  description                = "Detects execution of a renamed autohotkey.exe binary based on PE metadata fields"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoProductName contains "AutoHotkey" or ProcessVersionInfoFileDescription contains "AutoHotkey" or (ProcessVersionInfoOriginalFileName in~ ("AutoHotkey.exe", "AutoHotkey.rc"))) and (not(((FolderPath endswith "\\AutoHotkey.exe" or FolderPath endswith "\\AutoHotkey32.exe" or FolderPath endswith "\\AutoHotkey32_UIA.exe" or FolderPath endswith "\\AutoHotkey64.exe" or FolderPath endswith "\\AutoHotkey64_UIA.exe" or FolderPath endswith "\\AutoHotkeyA32.exe" or FolderPath endswith "\\AutoHotkeyA32_UIA.exe" or FolderPath endswith "\\AutoHotkeyU32.exe" or FolderPath endswith "\\AutoHotkeyU32_UIA.exe" or FolderPath endswith "\\AutoHotkeyU64.exe" or FolderPath endswith "\\AutoHotkeyU64_UIA.exe") or FolderPath contains "\\AutoHotkey")))
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}