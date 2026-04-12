resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_create_new_dmsasvc_account" {
  name                       = "proc_creation_win_create_new_dmsasvc_account"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New DMSA Service Account Created in Specific OUs"
  description                = <<DESC
    Detects the creation of a dMSASvc account using the New-ADServiceAccount cmdlet in certain OUs. The fact that the Cmdlet is used to create a dMSASvc account in a specific OU is highly suspicious. It is a pattern trying to exploit the BadSuccessor privilege escalation vulnerability in Windows Server 2025. On top of that, if the user that is creating the dMSASvc account is not a legitimate administrator or does not have the necessary permissions, it is a strong signal of an attempted or successful abuse of the BaDSuccessor vulnerability for privilege escalation within the Windows Server 2025 Active Directory environment.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_create_new_dmsasvc_account.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "New-ADServiceAccount" and ProcessCommandLine contains "-CreateDelegatedServiceAccount" and ProcessCommandLine contains "-path") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\powershell_ise.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell.exe", "pwsh.dll", "powershell_ise.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "InitialAccess", "DefenseEvasion", "Persistence"]
  techniques                 = ["T1078", "T1098"]
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