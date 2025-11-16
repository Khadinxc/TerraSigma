resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_provlaunch_exe_child_process" {
  name                       = "suspicious_provlaunch_exe_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Provlaunch.EXE Child Process"
  description                = "Detects suspicious child processes of \"provlaunch.exe\" which might indicate potential abuse to proxy execution."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\calc.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\notepad.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\wscript.exe") or (FolderPath contains ":\\PerfLogs\\" or FolderPath contains ":\\Temp\\" or FolderPath contains ":\\Users\\Public\\" or FolderPath contains "\\AppData\\Temp\\" or FolderPath contains "\\Windows\\System32\\Tasks\\" or FolderPath contains "\\Windows\\Tasks\\" or FolderPath contains "\\Windows\\Temp\\")) and InitiatingProcessFolderPath endswith "\\provlaunch.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}