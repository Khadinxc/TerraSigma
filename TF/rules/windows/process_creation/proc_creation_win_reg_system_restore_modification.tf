resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_reg_system_restore_modification" {
  name                       = "proc_creation_win_reg_system_restore_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Restore Registry Modification via CommandLine"
  description                = <<DESC
    Detects system restore registry modification via command line, which can be used by adversaries to disable system restore on the computer.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_system_restore_modification.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " add " or ProcessCommandLine contains "Set-ItemProperty" or ProcessCommandLine contains "New-ItemProperty") and (ProcessCommandLine contains "DisableConfig" or ProcessCommandLine contains "DisableSR") and (ProcessCommandLine contains "\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore" or ProcessCommandLine contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell.exe", "pwsh.dll", "reg.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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