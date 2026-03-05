resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_import_module" {
  name                       = "proc_creation_win_powershell_import_module"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Import New Module Via PowerShell CommandLine"
  description                = <<DESC
    Detects usage of the "Import-Module" cmdlet in order to add new Cmdlets to the current PowerShell session

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_powershell_import_module.yml

    False Positives:
    - Depending on the environement, many legitimate scripts will import modules inline. This rule is targeted for hunting purposes.
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "Import-Module " or ProcessCommandLine contains "ipmo ") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))) and (not(((ProcessCommandLine contains ":\\Program Files\\Microsoft Visual Studio\\" and ProcessCommandLine contains "Tools\\Microsoft.VisualStudio.DevShell.dll") and (InitiatingProcessFolderPath contains ":\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_" or InitiatingProcessFolderPath contains ":\\Windows\\System32\\cmd.exe"))))
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