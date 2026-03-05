resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_defender_default_action_modified" {
  name                       = "proc_creation_win_defender_default_action_modified"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction'"
  description                = <<DESC
    Detects the use of PowerShell to execute the 'Set-MpPreference' cmdlet to configure Windows Defender's threat severity default action to 'Allow' (value '6') or 'NoAction' (value '9'). This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level. An attacker might use this technique via the command line to bypass defenses before executing payloads.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_defender_default_action_modified.yml

    False Positives:
    - Highly unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-LowThreatDefaultAction" or ProcessCommandLine contains "-ModerateThreatDefaultAction" or ProcessCommandLine contains "-HighThreatDefaultAction" or ProcessCommandLine contains "-SevereThreatDefaultAction" or ProcessCommandLine contains "-ltdefac " or ProcessCommandLine contains "-mtdefac " or ProcessCommandLine contains "-htdefac " or ProcessCommandLine contains "-stdefac ") and ProcessCommandLine contains "Set-MpPreference" and (ProcessCommandLine contains "Allow" or ProcessCommandLine contains "6" or ProcessCommandLine contains "NoAction" or ProcessCommandLine contains "9")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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