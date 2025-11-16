resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_execution_of_pdqdeployrunner" {
  name                       = "potentially_suspicious_execution_of_pdqdeployrunner"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Execution Of PDQDeployRunner"
  description                = "Detects suspicious execution of \"PDQDeployRunner\" which is part of the PDQDeploy service stack that is responsible for executing commands and packages on a remote machines - Legitimate use of the PDQDeploy tool to execute these commands"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\bash.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\csc.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\dllhost.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\scriptrunner.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\wsl.exe") or (FolderPath contains ":\\ProgramData\\" or FolderPath contains ":\\Users\\Public\\" or FolderPath contains ":\\Windows\\TEMP\\" or FolderPath contains "\\AppData\\Local\\Temp") or (ProcessCommandLine contains " -decode " or ProcessCommandLine contains " -enc " or ProcessCommandLine contains " -encodedcommand " or ProcessCommandLine contains " -w hidden" or ProcessCommandLine contains "DownloadString" or ProcessCommandLine contains "FromBase64String" or ProcessCommandLine contains "http" or ProcessCommandLine contains "iex " or ProcessCommandLine contains "Invoke-")) and InitiatingProcessFolderPath contains "\\PDQDeployRunner-"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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