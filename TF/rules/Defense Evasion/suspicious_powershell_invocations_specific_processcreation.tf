resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_powershell_invocations_specific_processcreation" {
  name                       = "suspicious_powershell_invocations_specific_processcreation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PowerShell Invocations - Specific - ProcessCreation"
  description                = "Detects suspicious PowerShell invocation command parameters"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "-nop" and ProcessCommandLine contains " -w " and ProcessCommandLine contains "hidden" and ProcessCommandLine contains " -c " and ProcessCommandLine contains "[Convert]::FromBase64String") or (ProcessCommandLine contains " -w " and ProcessCommandLine contains "hidden" and ProcessCommandLine contains "-ep" and ProcessCommandLine contains "bypass" and ProcessCommandLine contains "-Enc") or (ProcessCommandLine contains " -w " and ProcessCommandLine contains "hidden" and ProcessCommandLine contains "-noni" and ProcessCommandLine contains "-nop" and ProcessCommandLine contains " -c " and ProcessCommandLine contains "iex" and ProcessCommandLine contains "New-Object") or (ProcessCommandLine contains "iex" and ProcessCommandLine contains "New-Object" and ProcessCommandLine contains "Net.WebClient" and ProcessCommandLine contains ".Download") or (ProcessCommandLine contains "powershell" and ProcessCommandLine contains "reg" and ProcessCommandLine contains "add" and ProcessCommandLine contains "\\software\\") or (ProcessCommandLine contains "bypass" and ProcessCommandLine contains "-noprofile" and ProcessCommandLine contains "-windowstyle" and ProcessCommandLine contains "hidden" and ProcessCommandLine contains "new-object" and ProcessCommandLine contains "system.net.webclient" and ProcessCommandLine contains ".download")) and (not((ProcessCommandLine contains "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1" or ProcessCommandLine contains "Write-ChocolateyWarning")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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