resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_mshta_exe_execution_patterns" {
  name                       = "suspicious_mshta_exe_execution_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Mshta.EXE Execution Patterns"
  description                = "Detects suspicious mshta process execution patterns"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\mshta.exe" or ProcessVersionInfoOriginalFileName =~ "MSHTA.EXE") and ((ProcessCommandLine contains "\\AppData\\Local\\" or ProcessCommandLine contains "C:\\ProgramData\\" or ProcessCommandLine contains "C:\\Users\\Public\\" or ProcessCommandLine contains "C:\\Windows\\Temp\\") and (InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe"))) or ((FolderPath endswith "\\mshta.exe" or ProcessVersionInfoOriginalFileName =~ "MSHTA.EXE") and (not(((FolderPath startswith "C:\\Windows\\System32\\" or FolderPath startswith "C:\\Windows\\SysWOW64\\") or (ProcessCommandLine contains ".htm" or ProcessCommandLine contains ".hta") or (ProcessCommandLine endswith "mshta.exe" or ProcessCommandLine endswith "mshta")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1106"]
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