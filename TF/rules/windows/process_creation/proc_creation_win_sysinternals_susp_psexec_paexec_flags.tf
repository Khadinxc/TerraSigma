resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_sysinternals_susp_psexec_paexec_flags" {
  name                       = "proc_creation_win_sysinternals_susp_psexec_paexec_flags"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Privilege Escalation To LOCAL SYSTEM"
  description                = <<DESC
    Detects unknown program using commandline flags usually used by tools such as PsExec and PAExec to start programs with SYSTEM Privileges

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_susp_psexec_paexec_flags.yml

    False Positives:
    - Weird admins that rename their tools
    - Software companies that bundle PsExec/PAExec with their software and rename it, so that it is less embarrassing
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -s cmd" or ProcessCommandLine contains " /s cmd" or ProcessCommandLine contains " –s cmd" or ProcessCommandLine contains " —s cmd" or ProcessCommandLine contains " ―s cmd" or ProcessCommandLine contains " -s -i cmd" or ProcessCommandLine contains " -s /i cmd" or ProcessCommandLine contains " -s –i cmd" or ProcessCommandLine contains " -s —i cmd" or ProcessCommandLine contains " -s ―i cmd" or ProcessCommandLine contains " /s -i cmd" or ProcessCommandLine contains " /s /i cmd" or ProcessCommandLine contains " /s –i cmd" or ProcessCommandLine contains " /s —i cmd" or ProcessCommandLine contains " /s ―i cmd" or ProcessCommandLine contains " –s -i cmd" or ProcessCommandLine contains " –s /i cmd" or ProcessCommandLine contains " –s –i cmd" or ProcessCommandLine contains " –s —i cmd" or ProcessCommandLine contains " –s ―i cmd" or ProcessCommandLine contains " —s -i cmd" or ProcessCommandLine contains " —s /i cmd" or ProcessCommandLine contains " —s –i cmd" or ProcessCommandLine contains " —s —i cmd" or ProcessCommandLine contains " —s ―i cmd" or ProcessCommandLine contains " ―s -i cmd" or ProcessCommandLine contains " ―s /i cmd" or ProcessCommandLine contains " ―s –i cmd" or ProcessCommandLine contains " ―s —i cmd" or ProcessCommandLine contains " ―s ―i cmd" or ProcessCommandLine contains " -i -s cmd" or ProcessCommandLine contains " -i /s cmd" or ProcessCommandLine contains " -i –s cmd" or ProcessCommandLine contains " -i —s cmd" or ProcessCommandLine contains " -i ―s cmd" or ProcessCommandLine contains " /i -s cmd" or ProcessCommandLine contains " /i /s cmd" or ProcessCommandLine contains " /i –s cmd" or ProcessCommandLine contains " /i —s cmd" or ProcessCommandLine contains " /i ―s cmd" or ProcessCommandLine contains " –i -s cmd" or ProcessCommandLine contains " –i /s cmd" or ProcessCommandLine contains " –i –s cmd" or ProcessCommandLine contains " –i —s cmd" or ProcessCommandLine contains " –i ―s cmd" or ProcessCommandLine contains " —i -s cmd" or ProcessCommandLine contains " —i /s cmd" or ProcessCommandLine contains " —i –s cmd" or ProcessCommandLine contains " —i —s cmd" or ProcessCommandLine contains " —i ―s cmd" or ProcessCommandLine contains " ―i -s cmd" or ProcessCommandLine contains " ―i /s cmd" or ProcessCommandLine contains " ―i –s cmd" or ProcessCommandLine contains " ―i —s cmd" or ProcessCommandLine contains " ―i ―s cmd" or ProcessCommandLine contains " -s pwsh" or ProcessCommandLine contains " /s pwsh" or ProcessCommandLine contains " –s pwsh" or ProcessCommandLine contains " —s pwsh" or ProcessCommandLine contains " ―s pwsh" or ProcessCommandLine contains " -s -i pwsh" or ProcessCommandLine contains " -s /i pwsh" or ProcessCommandLine contains " -s –i pwsh" or ProcessCommandLine contains " -s —i pwsh" or ProcessCommandLine contains " -s ―i pwsh" or ProcessCommandLine contains " /s -i pwsh" or ProcessCommandLine contains " /s /i pwsh" or ProcessCommandLine contains " /s –i pwsh" or ProcessCommandLine contains " /s —i pwsh" or ProcessCommandLine contains " /s ―i pwsh" or ProcessCommandLine contains " –s -i pwsh" or ProcessCommandLine contains " –s /i pwsh" or ProcessCommandLine contains " –s –i pwsh" or ProcessCommandLine contains " –s —i pwsh" or ProcessCommandLine contains " –s ―i pwsh" or ProcessCommandLine contains " —s -i pwsh" or ProcessCommandLine contains " —s /i pwsh" or ProcessCommandLine contains " —s –i pwsh" or ProcessCommandLine contains " —s —i pwsh" or ProcessCommandLine contains " —s ―i pwsh" or ProcessCommandLine contains " ―s -i pwsh" or ProcessCommandLine contains " ―s /i pwsh" or ProcessCommandLine contains " ―s –i pwsh" or ProcessCommandLine contains " ―s —i pwsh" or ProcessCommandLine contains " ―s ―i pwsh" or ProcessCommandLine contains " -i -s pwsh" or ProcessCommandLine contains " -i /s pwsh" or ProcessCommandLine contains " -i –s pwsh" or ProcessCommandLine contains " -i —s pwsh" or ProcessCommandLine contains " -i ―s pwsh" or ProcessCommandLine contains " /i -s pwsh" or ProcessCommandLine contains " /i /s pwsh" or ProcessCommandLine contains " /i –s pwsh" or ProcessCommandLine contains " /i —s pwsh" or ProcessCommandLine contains " /i ―s pwsh" or ProcessCommandLine contains " –i -s pwsh" or ProcessCommandLine contains " –i /s pwsh" or ProcessCommandLine contains " –i –s pwsh" or ProcessCommandLine contains " –i —s pwsh" or ProcessCommandLine contains " –i ―s pwsh" or ProcessCommandLine contains " —i -s pwsh" or ProcessCommandLine contains " —i /s pwsh" or ProcessCommandLine contains " —i –s pwsh" or ProcessCommandLine contains " —i —s pwsh" or ProcessCommandLine contains " —i ―s pwsh" or ProcessCommandLine contains " ―i -s pwsh" or ProcessCommandLine contains " ―i /s pwsh" or ProcessCommandLine contains " ―i –s pwsh" or ProcessCommandLine contains " ―i —s pwsh" or ProcessCommandLine contains " ―i ―s pwsh" or ProcessCommandLine contains " -s powershell" or ProcessCommandLine contains " /s powershell" or ProcessCommandLine contains " –s powershell" or ProcessCommandLine contains " —s powershell" or ProcessCommandLine contains " ―s powershell" or ProcessCommandLine contains " -s -i powershell" or ProcessCommandLine contains " -s /i powershell" or ProcessCommandLine contains " -s –i powershell" or ProcessCommandLine contains " -s —i powershell" or ProcessCommandLine contains " -s ―i powershell" or ProcessCommandLine contains " /s -i powershell" or ProcessCommandLine contains " /s /i powershell" or ProcessCommandLine contains " /s –i powershell" or ProcessCommandLine contains " /s —i powershell" or ProcessCommandLine contains " /s ―i powershell" or ProcessCommandLine contains " –s -i powershell" or ProcessCommandLine contains " –s /i powershell" or ProcessCommandLine contains " –s –i powershell" or ProcessCommandLine contains " –s —i powershell" or ProcessCommandLine contains " –s ―i powershell" or ProcessCommandLine contains " —s -i powershell" or ProcessCommandLine contains " —s /i powershell" or ProcessCommandLine contains " —s –i powershell" or ProcessCommandLine contains " —s —i powershell" or ProcessCommandLine contains " —s ―i powershell" or ProcessCommandLine contains " ―s -i powershell" or ProcessCommandLine contains " ―s /i powershell" or ProcessCommandLine contains " ―s –i powershell" or ProcessCommandLine contains " ―s —i powershell" or ProcessCommandLine contains " ―s ―i powershell" or ProcessCommandLine contains " -i -s powershell" or ProcessCommandLine contains " -i /s powershell" or ProcessCommandLine contains " -i –s powershell" or ProcessCommandLine contains " -i —s powershell" or ProcessCommandLine contains " -i ―s powershell" or ProcessCommandLine contains " /i -s powershell" or ProcessCommandLine contains " /i /s powershell" or ProcessCommandLine contains " /i –s powershell" or ProcessCommandLine contains " /i —s powershell" or ProcessCommandLine contains " /i ―s powershell" or ProcessCommandLine contains " –i -s powershell" or ProcessCommandLine contains " –i /s powershell" or ProcessCommandLine contains " –i –s powershell" or ProcessCommandLine contains " –i —s powershell" or ProcessCommandLine contains " –i ―s powershell" or ProcessCommandLine contains " —i -s powershell" or ProcessCommandLine contains " —i /s powershell" or ProcessCommandLine contains " —i –s powershell" or ProcessCommandLine contains " —i —s powershell" or ProcessCommandLine contains " —i ―s powershell" or ProcessCommandLine contains " ―i -s powershell" or ProcessCommandLine contains " ―i /s powershell" or ProcessCommandLine contains " ―i –s powershell" or ProcessCommandLine contains " ―i —s powershell" or ProcessCommandLine contains " ―i ―s powershell") and (not((ProcessCommandLine contains "paexec" or ProcessCommandLine contains "PsExec" or ProcessCommandLine contains "accepteula")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1587"]
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
}