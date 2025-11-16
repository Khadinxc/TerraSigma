resource "azurerm_sentinel_alert_rule_scheduled" "vmtoolsd_suspicious_child_process" {
  name                       = "vmtoolsd_suspicious_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "VMToolsd Suspicious Child Process"
  description                = "Detects suspicious child process creations of VMware Tools process which may indicate persistence setup - Legitimate use by VM administrator"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\wscript.exe") or (ProcessVersionInfoOriginalFileName in~ ("Cmd.Exe", "cscript.exe", "MSHTA.EXE", "PowerShell.EXE", "pwsh.dll", "REGSVR32.EXE", "RUNDLL32.EXE", "wscript.exe"))) and InitiatingProcessFolderPath endswith "\\vmtoolsd.exe") and (not(((ProcessCommandLine =~ "" and FolderPath endswith "\\cmd.exe") or (isnull(ProcessCommandLine) and FolderPath endswith "\\cmd.exe") or ((ProcessCommandLine contains "\\VMware\\VMware Tools\\poweron-vm-default.bat" or ProcessCommandLine contains "\\VMware\\VMware Tools\\poweroff-vm-default.bat" or ProcessCommandLine contains "\\VMware\\VMware Tools\\resume-vm-default.bat" or ProcessCommandLine contains "\\VMware\\VMware Tools\\suspend-vm-default.bat") and FolderPath endswith "\\cmd.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence"]
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