resource "azurerm_sentinel_alert_rule_scheduled" "lol_binary_copied_from_system_directory" {
  name                       = "lol_binary_copied_from_system_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LOL-Binary Copied From System Directory"
  description                = "Detects a suspicious copy operation that tries to copy a known LOLBIN from system (System32, SysWOW64, WinSxS) directories to another on disk in order to bypass detections based on locations."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "copy " and FolderPath endswith "\\cmd.exe") or ((FolderPath endswith "\\robocopy.exe" or FolderPath endswith "\\xcopy.exe") or (ProcessVersionInfoOriginalFileName in~ ("robocopy.exe", "XCOPY.EXE"))) or ((ProcessCommandLine contains "copy-item" or ProcessCommandLine contains " copy " or ProcessCommandLine contains "cpi " or ProcessCommandLine contains " cp ") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe"))) and ((ProcessCommandLine contains "\\bitsadmin.exe" or ProcessCommandLine contains "\\calc.exe" or ProcessCommandLine contains "\\certutil.exe" or ProcessCommandLine contains "\\cmdl32.exe" or ProcessCommandLine contains "\\cscript.exe" or ProcessCommandLine contains "\\mshta.exe" or ProcessCommandLine contains "\\rundll32.exe" or ProcessCommandLine contains "\\wscript.exe") and (ProcessCommandLine contains "\\System32" or ProcessCommandLine contains "\\SysWOW64" or ProcessCommandLine contains "\\WinSxS"))
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