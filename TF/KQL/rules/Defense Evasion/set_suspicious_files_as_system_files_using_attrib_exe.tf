resource "azurerm_sentinel_alert_rule_scheduled" "set_suspicious_files_as_system_files_using_attrib_exe" {
  name                       = "set_suspicious_files_as_system_files_using_attrib_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Set Suspicious Files as System Files Using Attrib.EXE"
  description                = "Detects the usage of attrib with the \"+s\" option to set scripts or executables located in suspicious locations as system files to hide them from users and make them unable to be deleted with simple rights. The rule limits the search to specific extensions and directories to avoid FPs"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " +s" and (ProcessCommandLine contains ".bat" or ProcessCommandLine contains ".dll" or ProcessCommandLine contains ".exe" or ProcessCommandLine contains ".hta" or ProcessCommandLine contains ".ps1" or ProcessCommandLine contains ".vbe" or ProcessCommandLine contains ".vbs") and (FolderPath endswith "\\attrib.exe" or ProcessVersionInfoOriginalFileName =~ "ATTRIB.EXE") and (ProcessCommandLine contains " %" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\AppData\\Local\\" or ProcessCommandLine contains "\\ProgramData\\" or ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Windows\\Temp\\")) and (not((ProcessCommandLine contains "\\Windows\\TEMP\\" and ProcessCommandLine contains ".exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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