resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_cmdlet_invocation_via_exported_commands_array_index" {
  name                       = "proc_creation_win_powershell_cmdlet_invocation_via_exported_commands_array_index"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Dynamic Module Invocation Via ExportedCommands Array Index"
  description                = <<DESC
    Detects PowerShell processes invoked with obfuscated command lines that enumerate Microsoft.PowerShell.Utility exported commands and invoke cmdlets indirectly by array index. This technique is used to evade detections that look for explicit strings such as Invoke-RestMethod or Invoke-Expression.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_cmdlet_invocation_via_exported_commands_array_index.yml

    False Positives:
    - Legitimate use of exported commands array indexing during PowerShell command execution (should be rare)
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell.exe", "pwsh.dll"))) and ProcessCommandLine =~ "*[*]*" and ((ProcessCommandLine contains "Get-Module " or ProcessCommandLine contains "gmo ") and (ProcessCommandLine contains "ListAvailable" and ProcessCommandLine contains "Microsoft.PowerShell.Utility" and ProcessCommandLine contains "ExportedCommands" and ProcessCommandLine contains "Values"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1027", "T1059"]
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