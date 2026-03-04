resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_agentexecutor_powershell_execution" {
  name                       = "suspicious_agentexecutor_powershell_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious AgentExecutor PowerShell Execution"
  description                = "Detects execution of the AgentExecutor.exe binary. Which can be abused as a LOLBIN to execute powershell scripts with the ExecutionPolicy \"Bypass\" or any binary named \"powershell.exe\" located in the path provided by 6th positional argument | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/suspicious_agentexecutor_powershell_execution.yml"
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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