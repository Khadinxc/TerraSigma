resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_applocker_policy_discovery_via_get_applockerpolicy" {
  name                       = "proc_creation_win_powershell_applocker_policy_discovery_via_get_applockerpolicy"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell AppLocker Policy Discovery Via Get-AppLockerPolicy"
  description                = <<DESC
    Detects AppLocker policy enumeration attempts via PowerShell using the Get-AppLockerPolicy cmdlet and an policy scope of either Effective, LDAP, or Local.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_applocker_policy_discovery_via_get_applockerpolicy.yml

    False Positives:
    - PowerShell-based AppLocker auditing and policy troubleshooting by administrators.
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Get-AppLockerPolicy" and (ProcessCommandLine contains " -Effective" or ProcessCommandLine contains " /Effective" or ProcessCommandLine contains " –Effective" or ProcessCommandLine contains " —Effective" or ProcessCommandLine contains " ―Effective" or ProcessCommandLine contains " -Ldap " or ProcessCommandLine contains " /Ldap " or ProcessCommandLine contains " –Ldap " or ProcessCommandLine contains " —Ldap " or ProcessCommandLine contains " ―Ldap " or ProcessCommandLine contains " -Local" or ProcessCommandLine contains " /Local" or ProcessCommandLine contains " –Local" or ProcessCommandLine contains " —Local" or ProcessCommandLine contains " ―Local") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1518"]
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