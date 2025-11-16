resource "azurerm_sentinel_alert_rule_scheduled" "potential_powershell_execution_via_dll" {
  name                       = "potential_powershell_execution_via_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PowerShell Execution Via DLL"
  description                = "Detects potential PowerShell execution from a DLL instead of the usual PowerShell process as seen used in PowerShdll. This detection assumes that PowerShell commands are passed via the CommandLine."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Default.GetString" or ProcessCommandLine contains "DownloadString" or ProcessCommandLine contains "FromBase64String" or ProcessCommandLine contains "ICM " or ProcessCommandLine contains "IEX " or ProcessCommandLine contains "Invoke-Command" or ProcessCommandLine contains "Invoke-Expression") and ((FolderPath endswith "\\InstallUtil.exe" or FolderPath endswith "\\RegAsm.exe" or FolderPath endswith "\\RegSvcs.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe") or (ProcessVersionInfoOriginalFileName in~ ("InstallUtil.exe", "RegAsm.exe", "RegSvcs.exe", "REGSVR32.EXE", "RUNDLL32.EXE")))
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