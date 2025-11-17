resource "azurerm_sentinel_alert_rule_scheduled" "agentexecutor_powershell_execution" {
  name                       = "agentexecutor_powershell_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "AgentExecutor PowerShell Execution"
  description                = "Detects execution of the AgentExecutor.exe binary. Which can be abused as a LOLBIN to execute powershell scripts with the ExecutionPolicy \"Bypass\" or any binary named \"powershell.exe\" located in the path provided by 6th positional argument - Legitimate use via Intune management. You exclude script paths and names to reduce FP rate"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -powershell" or ProcessCommandLine contains " -remediationScript") and (FolderPath =~ "\\AgentExecutor.exe" or ProcessVersionInfoOriginalFileName =~ "AgentExecutor.exe")) and (not(InitiatingProcessFolderPath endswith "\\Microsoft.Management.Services.IntuneWindowsAgent.exe"))
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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