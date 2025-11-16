resource "azurerm_sentinel_alert_rule_scheduled" "powershell_defender_threat_severity_default_action_set_to_allow_or_noaction" {
  name                       = "powershell_defender_threat_severity_default_action_set_to_allow_or_noaction"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction'"
  description                = "Detects the use of PowerShell to execute the 'Set-MpPreference' cmdlet to configure Windows Defender's threat severity default action to 'Allow' (value '6') or 'NoAction' (value '9'). This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level. An attacker might use this technique via the command line to bypass defenses before executing payloads. - Highly unlikely"
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}