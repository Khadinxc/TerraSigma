resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_apt_turla_commands_critical" {
  name                       = "proc_creation_win_apt_turla_commands_critical"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Turla Group Lateral Movement"
  description                = <<DESC
    Detects automated lateral movement by Turla group

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2014/TA/Turla/proc_creation_win_apt_turla_commands_critical.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine startswith "net use \\\\%DomainController%\\C$ \"P@ssw0rd\" " or (ProcessCommandLine contains "dir c:\\" and ProcessCommandLine contains ".doc" and ProcessCommandLine contains " /s") or (ProcessCommandLine contains "dir %TEMP%\\" and ProcessCommandLine contains ".exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement", "Discovery"]
  techniques                 = ["T1059", "T1021", "T1083", "T1135"]
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