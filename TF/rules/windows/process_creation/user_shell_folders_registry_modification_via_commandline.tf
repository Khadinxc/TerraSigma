resource "azurerm_sentinel_alert_rule_scheduled" "user_shell_folders_registry_modification_via_commandline" {
  name                       = "user_shell_folders_registry_modification_via_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "User Shell Folders Registry Modification via CommandLine"
  description                = "Detects modifications to User Shell Folders registry values via reg.exe or PowerShell, which could indicate persistence attempts. Attackers may modify User Shell Folders registry values to point to malicious executables or scripts that will be executed during startup. This technique is often used to maintain persistence on a compromised system by ensuring that malicious payloads are executed automatically. - Usage of reg.exe or PowerShell to modify User Shell Folders for legitimate purposes; but rare."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " add " or ProcessCommandLine contains "New-ItemProperty" or ProcessCommandLine contains "Set-ItemProperty" or ProcessCommandLine contains "si ") and (ProcessCommandLine contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" or ProcessCommandLine contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders") and ProcessCommandLine contains "Startup" and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell.exe", "pwsh.dll", "reg.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1547", "T1112"]
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