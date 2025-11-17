resource "azurerm_sentinel_alert_rule_scheduled" "psexec_paexec_escalation_to_local_system" {
  name                       = "psexec_paexec_escalation_to_local_system"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PsExec/PAExec Escalation to LOCAL SYSTEM"
  description                = "Detects suspicious commandline flags used by PsExec and PAExec to escalate a command line to LOCAL_SYSTEM rights - Admins that use PsExec or PAExec to escalate to the SYSTEM account for maintenance purposes (rare) - Users that debug Microsoft Intune issues using the commands mentioned in the official documentation; see https://learn.microsoft.com/en-us/mem/intune/apps/intune-management-extension"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "psexec" or ProcessCommandLine contains "paexec" or ProcessCommandLine contains "accepteula") and (ProcessCommandLine contains " -s cmd" or ProcessCommandLine contains " /s cmd" or ProcessCommandLine contains " –s cmd" or ProcessCommandLine contains " —s cmd" or ProcessCommandLine contains " ―s cmd" or ProcessCommandLine contains " -s -i cmd" or ProcessCommandLine contains " -s /i cmd" or ProcessCommandLine contains " -s –i cmd" or ProcessCommandLine contains " -s —i cmd" or ProcessCommandLine contains " -s ―i cmd" or ProcessCommandLine contains " /s -i cmd" or ProcessCommandLine contains " /s /i cmd" or ProcessCommandLine contains " /s –i cmd" or ProcessCommandLine contains " /s —i cmd" or ProcessCommandLine contains " /s ―i cmd" or ProcessCommandLine contains " –s -i cmd" or ProcessCommandLine contains " –s /i cmd" or ProcessCommandLine contains " –s –i cmd" or ProcessCommandLine contains " –s —i cmd" or ProcessCommandLine contains " –s ―i cmd" or ProcessCommandLine contains " —s -i cmd" or ProcessCommandLine contains " —s /i cmd" or ProcessCommandLine contains " —s –i cmd" or ProcessCommandLine contains " —s —i cmd" or ProcessCommandLine contains " —s ―i cmd" or ProcessCommandLine contains " ―s -i cmd" or ProcessCommandLine contains " ―s /i cmd" or ProcessCommandLine contains " ―s –i cmd" or ProcessCommandLine contains " ―s —i cmd" or ProcessCommandLine contains " ―s ―i cmd" or ProcessCommandLine contains " -i -s cmd" or ProcessCommandLine contains " -i /s cmd" or ProcessCommandLine contains " -i –s cmd" or ProcessCommandLine contains " -i —s cmd" or ProcessCommandLine contains " -i ―s cmd" or ProcessCommandLine contains " /i -s cmd" or ProcessCommandLine contains " /i /s cmd" or ProcessCommandLine contains " /i –s cmd" or ProcessCommandLine contains " /i —s cmd" or ProcessCommandLine contains " /i ―s cmd" or ProcessCommandLine contains " –i -s cmd" or ProcessCommandLine contains " –i /s cmd" or ProcessCommandLine contains " –i –s cmd" or ProcessCommandLine contains " –i —s cmd" or ProcessCommandLine contains " –i ―s cmd" or ProcessCommandLine contains " —i -s cmd" or ProcessCommandLine contains " —i /s cmd" or ProcessCommandLine contains " —i –s cmd" or ProcessCommandLine contains " —i —s cmd" or ProcessCommandLine contains " —i ―s cmd" or ProcessCommandLine contains " ―i -s cmd" or ProcessCommandLine contains " ―i /s cmd" or ProcessCommandLine contains " ―i –s cmd" or ProcessCommandLine contains " ―i —s cmd" or ProcessCommandLine contains " ―i ―s cmd" or ProcessCommandLine contains " -s pwsh" or ProcessCommandLine contains " /s pwsh" or ProcessCommandLine contains " –s pwsh" or ProcessCommandLine contains " —s pwsh" or ProcessCommandLine contains " ―s pwsh" or ProcessCommandLine contains " -s -i pwsh" or ProcessCommandLine contains " -s /i pwsh" or ProcessCommandLine contains " -s –i pwsh" or ProcessCommandLine contains " -s —i pwsh" or ProcessCommandLine contains " -s ―i pwsh" or ProcessCommandLine contains " /s -i pwsh" or ProcessCommandLine contains " /s /i pwsh" or ProcessCommandLine contains " /s –i pwsh" or ProcessCommandLine contains " /s —i pwsh" or ProcessCommandLine contains " /s ―i pwsh" or ProcessCommandLine contains " –s -i pwsh" or ProcessCommandLine contains " –s /i pwsh" or ProcessCommandLine contains " –s –i pwsh" or ProcessCommandLine contains " –s —i pwsh" or ProcessCommandLine contains " –s ―i pwsh" or ProcessCommandLine contains " —s -i pwsh" or ProcessCommandLine contains " —s /i pwsh" or ProcessCommandLine contains " —s –i pwsh" or ProcessCommandLine contains " —s —i pwsh" or ProcessCommandLine contains " —s ―i pwsh" or ProcessCommandLine contains " ―s -i pwsh" or ProcessCommandLine contains " ―s /i pwsh" or ProcessCommandLine contains " ―s –i pwsh" or ProcessCommandLine contains " ―s —i pwsh" or ProcessCommandLine contains " ―s ―i pwsh" or ProcessCommandLine contains " -i -s pwsh" or ProcessCommandLine contains " -i /s pwsh" or ProcessCommandLine contains " -i –s pwsh" or ProcessCommandLine contains " -i —s pwsh" or ProcessCommandLine contains " -i ―s pwsh" or ProcessCommandLine contains " /i -s pwsh" or ProcessCommandLine contains " /i /s pwsh" or ProcessCommandLine contains " /i –s pwsh" or ProcessCommandLine contains " /i —s pwsh" or ProcessCommandLine contains " /i ―s pwsh" or ProcessCommandLine contains " –i -s pwsh" or ProcessCommandLine contains " –i /s pwsh" or ProcessCommandLine contains " –i –s pwsh" or ProcessCommandLine contains " –i —s pwsh" or ProcessCommandLine contains " –i ―s pwsh" or ProcessCommandLine contains " —i -s pwsh" or ProcessCommandLine contains " —i /s pwsh" or ProcessCommandLine contains " —i –s pwsh" or ProcessCommandLine contains " —i —s pwsh" or ProcessCommandLine contains " —i ―s pwsh" or ProcessCommandLine contains " ―i -s pwsh" or ProcessCommandLine contains " ―i /s pwsh" or ProcessCommandLine contains " ―i –s pwsh" or ProcessCommandLine contains " ―i —s pwsh" or ProcessCommandLine contains " ―i ―s pwsh" or ProcessCommandLine contains " -s powershell" or ProcessCommandLine contains " /s powershell" or ProcessCommandLine contains " –s powershell" or ProcessCommandLine contains " —s powershell" or ProcessCommandLine contains " ―s powershell" or ProcessCommandLine contains " -s -i powershell" or ProcessCommandLine contains " -s /i powershell" or ProcessCommandLine contains " -s –i powershell" or ProcessCommandLine contains " -s —i powershell" or ProcessCommandLine contains " -s ―i powershell" or ProcessCommandLine contains " /s -i powershell" or ProcessCommandLine contains " /s /i powershell" or ProcessCommandLine contains " /s –i powershell" or ProcessCommandLine contains " /s —i powershell" or ProcessCommandLine contains " /s ―i powershell" or ProcessCommandLine contains " –s -i powershell" or ProcessCommandLine contains " –s /i powershell" or ProcessCommandLine contains " –s –i powershell" or ProcessCommandLine contains " –s —i powershell" or ProcessCommandLine contains " –s ―i powershell" or ProcessCommandLine contains " —s -i powershell" or ProcessCommandLine contains " —s /i powershell" or ProcessCommandLine contains " —s –i powershell" or ProcessCommandLine contains " —s —i powershell" or ProcessCommandLine contains " —s ―i powershell" or ProcessCommandLine contains " ―s -i powershell" or ProcessCommandLine contains " ―s /i powershell" or ProcessCommandLine contains " ―s –i powershell" or ProcessCommandLine contains " ―s —i powershell" or ProcessCommandLine contains " ―s ―i powershell" or ProcessCommandLine contains " -i -s powershell" or ProcessCommandLine contains " -i /s powershell" or ProcessCommandLine contains " -i –s powershell" or ProcessCommandLine contains " -i —s powershell" or ProcessCommandLine contains " -i ―s powershell" or ProcessCommandLine contains " /i -s powershell" or ProcessCommandLine contains " /i /s powershell" or ProcessCommandLine contains " /i –s powershell" or ProcessCommandLine contains " /i —s powershell" or ProcessCommandLine contains " /i ―s powershell" or ProcessCommandLine contains " –i -s powershell" or ProcessCommandLine contains " –i /s powershell" or ProcessCommandLine contains " –i –s powershell" or ProcessCommandLine contains " –i —s powershell" or ProcessCommandLine contains " –i ―s powershell" or ProcessCommandLine contains " —i -s powershell" or ProcessCommandLine contains " —i /s powershell" or ProcessCommandLine contains " —i –s powershell" or ProcessCommandLine contains " —i —s powershell" or ProcessCommandLine contains " —i ―s powershell" or ProcessCommandLine contains " ―i -s powershell" or ProcessCommandLine contains " ―i /s powershell" or ProcessCommandLine contains " ―i –s powershell" or ProcessCommandLine contains " ―i —s powershell" or ProcessCommandLine contains " ―i ―s powershell")
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
}