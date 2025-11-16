resource "azurerm_sentinel_alert_rule_scheduled" "computer_discovery_and_export_via_get_adcomputer_cmdlet" {
  name                       = "computer_discovery_and_export_via_get_adcomputer_cmdlet"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Computer Discovery And Export Via Get-ADComputer Cmdlet"
  description                = "Detects usage of the Get-ADComputer cmdlet to collect computer information and output it to a file - Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " > " or ProcessCommandLine contains " | Select " or ProcessCommandLine contains "Out-File" or ProcessCommandLine contains "Set-Content" or ProcessCommandLine contains "Add-Content") and (ProcessCommandLine contains "Get-ADComputer " and ProcessCommandLine contains " -Filter *")) and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1033"]
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