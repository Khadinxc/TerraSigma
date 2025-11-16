resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_copy_from_or_to_system_directory" {
  name                       = "suspicious_copy_from_or_to_system_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Copy From or To System Directory"
  description                = "Detects a suspicious copy operation that tries to copy a program from system (System32, SysWOW64, WinSxS) directories to another on disk. Often used to move LOLBINs such as 'certutil' or 'desktopimgdownldr' to a different location with a different name in order to bypass detections based on locations. - Depend on scripts and administrative tools used in the monitored environment (For example an admin scripts like https://www.itexperience.net/sccm-batch-files-and-32-bits-processes-on-64-bits-os/) - When cmd.exe and xcopy.exe are called directly - When the command contains the keywords but not in the correct order"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "copy " and FolderPath endswith "\\cmd.exe") or ((FolderPath endswith "\\robocopy.exe" or FolderPath endswith "\\xcopy.exe") or (ProcessVersionInfoOriginalFileName in~ ("robocopy.exe", "XCOPY.EXE"))) or ((ProcessCommandLine contains "copy-item" or ProcessCommandLine contains " copy " or ProcessCommandLine contains "cpi " or ProcessCommandLine contains " cp ") and (FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe"))) and (ProcessCommandLine contains "\\System32" or ProcessCommandLine contains "\\SysWOW64" or ProcessCommandLine contains "\\WinSxS") and (not(((ProcessCommandLine contains "C:\\Program Files\\Avira\\" or ProcessCommandLine contains "C:\\Program Files (x86)\\Avira\\") and (ProcessCommandLine contains "/c copy" and ProcessCommandLine contains "\\Temp\\" and ProcessCommandLine contains "\\avira_system_speedup.exe") and FolderPath endswith "\\cmd.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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