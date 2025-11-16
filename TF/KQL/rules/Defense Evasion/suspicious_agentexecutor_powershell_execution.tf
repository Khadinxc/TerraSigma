resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_agentexecutor_powershell_execution" {
  name                       = "suspicious_agentexecutor_powershell_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious AgentExecutor PowerShell Execution"
  description                = "Detects execution of the AgentExecutor.exe binary. Which can be abused as a LOLBIN to execute powershell scripts with the ExecutionPolicy \"Bypass\" or any binary named \"powershell.exe\" located in the path provided by 6th positional argument"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -powershell" or ProcessCommandLine contains " -remediationScript") and (FolderPath endswith "\\AgentExecutor.exe" or ProcessVersionInfoOriginalFileName =~ "AgentExecutor.exe")) and (not((InitiatingProcessFolderPath endswith "\\Microsoft.Management.Services.IntuneWindowsAgent.exe" or (ProcessCommandLine contains "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\" or ProcessCommandLine contains "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\"))))
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