resource "azurerm_sentinel_alert_rule_scheduled" "odbcconf_exe_suspicious_dll_location" {
  name                       = "odbcconf_exe_suspicious_dll_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Odbcconf.EXE Suspicious DLL Location"
  description                = "Detects execution of \"odbcconf\" where the path of the DLL being registered is located in a potentially suspicious location. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ":\\PerfLogs\\" or ProcessCommandLine contains ":\\ProgramData\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\Registration\\CRMLog" or ProcessCommandLine contains ":\\Windows\\System32\\com\\dmp\\" or ProcessCommandLine contains ":\\Windows\\System32\\FxsTmp\\" or ProcessCommandLine contains ":\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\" or ProcessCommandLine contains ":\\Windows\\System32\\spool\\drivers\\color\\" or ProcessCommandLine contains ":\\Windows\\System32\\spool\\PRINTERS\\" or ProcessCommandLine contains ":\\Windows\\System32\\spool\\SERVERS\\" or ProcessCommandLine contains ":\\Windows\\System32\\Tasks_Migrated\\" or ProcessCommandLine contains ":\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\" or ProcessCommandLine contains ":\\Windows\\SysWOW64\\com\\dmp\\" or ProcessCommandLine contains ":\\Windows\\SysWOW64\\FxsTmp\\" or ProcessCommandLine contains ":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\" or ProcessCommandLine contains ":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\" or ProcessCommandLine contains ":\\Windows\\Tasks\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains ":\\Windows\\Tracing\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\AppData\\Roaming\\") and (FolderPath endswith "\\odbcconf.exe" or ProcessVersionInfoOriginalFileName =~ "odbcconf.exe")
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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