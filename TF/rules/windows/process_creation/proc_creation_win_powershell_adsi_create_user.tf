resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_adsi_create_user" {
  name                       = "proc_creation_win_powershell_adsi_create_user"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New User Account Creation Attempt Via ADSI in CommandLine"
  description                = <<DESC
    Detects PowerShell command line arguments containing ADSI (Active Directory Service Interfaces) patterns trying to create a new user account via the WinNT or LDAP provider. This is an uncommon method to create user accounts and may indicate an attempt to evade detection by avoiding more commonly monitored commands such as "net user", "New-LocalUser" or "New-ADUser".

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_adsi_create_user.yml

    False Positives:
    - Legitimate administrative scripts that use ADSI to provision user accounts but should be rare in most environments
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "[ADSI]" and (ProcessCommandLine contains "WinNT://" or ProcessCommandLine contains "LDAP://") and (ProcessCommandLine contains ".Create(\"user" or ProcessCommandLine contains ".Create('user") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1136"]
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