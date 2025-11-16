resource "azurerm_sentinel_alert_rule_scheduled" "script_interpreter_execution_from_suspicious_folder" {
  name                       = "script_interpreter_execution_from_suspicious_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Script Interpreter Execution From Suspicious Folder"
  description                = "Detects a suspicious script execution in temporary folders or folders accessible by environment variables"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -ep bypass " or ProcessCommandLine contains " -ExecutionPolicy bypass " or ProcessCommandLine contains " -w hidden " or ProcessCommandLine contains "/e:javascript " or ProcessCommandLine contains "/e:Jscript " or ProcessCommandLine contains "/e:vbscript ") or (FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\wscript.exe") or (ProcessVersionInfoOriginalFileName in~ ("cscript.exe", "mshta.exe", "wscript.exe"))) and ((ProcessCommandLine contains ":\\Perflogs\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp" or ProcessCommandLine contains "\\AppData\\Roaming\\Temp" or ProcessCommandLine contains "\\Temporary Internet" or ProcessCommandLine contains "\\Windows\\Temp") or ((ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Favorites\\") or (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Favourites\\") or (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Contacts\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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