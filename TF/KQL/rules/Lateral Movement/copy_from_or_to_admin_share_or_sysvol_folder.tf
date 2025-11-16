resource "azurerm_sentinel_alert_rule_scheduled" "copy_from_or_to_admin_share_or_sysvol_folder" {
  name                       = "copy_from_or_to_admin_share_or_sysvol_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Copy From Or To Admin Share Or Sysvol Folder"
  description                = "Detects a copy command or a copy utility execution to or from an Admin share or remote - Administrative scripts"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\" and ProcessCommandLine contains "\\" and ProcessCommandLine contains "$") or ProcessCommandLine contains "\\Sysvol\\") and (((FolderPath endswith "\\robocopy.exe" or FolderPath endswith "\\xcopy.exe") or (ProcessVersionInfoOriginalFileName in~ ("robocopy.exe", "XCOPY.EXE"))) or (ProcessCommandLine contains "copy" and (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe")) or ((ProcessCommandLine contains "copy-item" or ProcessCommandLine contains "copy " or ProcessCommandLine contains "cpi " or ProcessCommandLine contains " cp " or ProcessCommandLine contains "move " or ProcessCommandLine contains " move-item" or ProcessCommandLine contains " mi " or ProcessCommandLine contains " mv ") and ((FolderPath contains "\\powershell_ise.exe" or FolderPath contains "\\powershell.exe" or FolderPath contains "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell_ise.exe", "PowerShell.EXE", "pwsh.dll")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement", "Collection", "Exfiltration"]
  techniques                 = ["T1039", "T1048", "T1021"]
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