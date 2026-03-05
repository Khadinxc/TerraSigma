resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_registry_install_reg_debugger_backdoor" {
  name                       = "proc_creation_win_registry_install_reg_debugger_backdoor"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Debugger Registration Cmdline"
  description                = <<DESC
    Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_registry_install_reg_debugger_backdoor.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\CurrentVersion\\Image File Execution Options\\" and (ProcessCommandLine contains "sethc.exe" or ProcessCommandLine contains "utilman.exe" or ProcessCommandLine contains "osk.exe" or ProcessCommandLine contains "magnify.exe" or ProcessCommandLine contains "narrator.exe" or ProcessCommandLine contains "displayswitch.exe" or ProcessCommandLine contains "atbroker.exe" or ProcessCommandLine contains "HelpPane.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1546"]
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