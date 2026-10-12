resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_wsl_installlocation_modification_via_cmdline" {
  name                       = "proc_creation_win_wsl_installlocation_modification_via_cmdline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious WSL InstallLocation Registry Key Modification Via CommandLine"
  description                = <<DESC
    Detects the use of reg.exe or PowerShell to modify the WSL InstallLocation registry key via command-line arguments. Legitimate modifications to this key are performed exclusively by the Windows Installer (msiexec.exe) during WSL package installation or update. Manual use of reg.exe or PowerShell to set this value strongly indicates an attempt to redirect WSL execution to a malicious binary.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wsl_installlocation_modification_via_cmdline.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " add " or ProcessCommandLine contains "New-ItemProperty" or ProcessCommandLine contains "Set-ItemProperty" or ProcessCommandLine contains "sp ") and (ProcessCommandLine contains "\\Lxss\\MSI" or ProcessCommandLine contains "/Lxss/MSI") and ProcessCommandLine contains "InstallLocation" and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell.exe", "pwsh.dll", "reg.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1112", "T1218"]
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