resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_modification_of_scheduled_tasks" {
  name                       = "suspicious_modification_of_scheduled_tasks"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Modification Of Scheduled Tasks"
  description                = "Detects when an attacker tries to modify an already existing scheduled tasks to run from a suspicious location Attackers can create a simple looking task in order to avoid detection on creation as it's often the most focused on Instead they modify the task after creation to include their malicious payload"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " /Change " and ProcessCommandLine contains " /TN ") and FolderPath endswith "\\schtasks.exe") and (ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "cmd /c " or ProcessCommandLine contains "cmd /k " or ProcessCommandLine contains "cmd /r " or ProcessCommandLine contains "cmd.exe /c " or ProcessCommandLine contains "cmd.exe /k " or ProcessCommandLine contains "cmd.exe /r " or ProcessCommandLine contains "powershell" or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "wscript" or ProcessCommandLine contains "cscript" or ProcessCommandLine contains "certutil" or ProcessCommandLine contains "bitsadmin" or ProcessCommandLine contains "bash.exe" or ProcessCommandLine contains "bash " or ProcessCommandLine contains "scrcons" or ProcessCommandLine contains "wmic " or ProcessCommandLine contains "wmic.exe" or ProcessCommandLine contains "forfiles" or ProcessCommandLine contains "scriptrunner" or ProcessCommandLine contains "hh.exe" or ProcessCommandLine contains "hh ") and (ProcessCommandLine contains "\\AppData\\Local\\Temp" or ProcessCommandLine contains "\\AppData\\Roaming\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\WINDOWS\\Temp\\" or ProcessCommandLine contains "\\Desktop\\" or ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Temporary Internet" or ProcessCommandLine contains "C:\\ProgramData\\" or ProcessCommandLine contains "C:\\Perflogs\\" or ProcessCommandLine contains "%ProgramData%" or ProcessCommandLine contains "%appdata%" or ProcessCommandLine contains "%comspec%" or ProcessCommandLine contains "%localappdata%")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "Execution"]
  techniques                 = ["T1053"]
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