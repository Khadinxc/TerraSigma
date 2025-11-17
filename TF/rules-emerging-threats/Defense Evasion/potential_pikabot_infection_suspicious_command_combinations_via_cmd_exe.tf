resource "azurerm_sentinel_alert_rule_scheduled" "potential_pikabot_infection_suspicious_command_combinations_via_cmd_exe" {
  name                       = "potential_pikabot_infection_suspicious_command_combinations_via_cmd_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Pikabot Infection - Suspicious Command Combinations Via Cmd.EXE"
  description                = "Detects the execution of concatenated commands via \"cmd.exe\". Pikabot often executes a combination of multiple commands via the command handler \"cmd /c\" in order to download and execute additional payloads. Commands such as \"curl\", \"wget\" in order to download extra payloads. \"ping\" and \"timeout\" are abused to introduce delays in the command execution and \"Rundll32\" is also used to execute malicious DLL files. In the observed Pikabot infections, a combination of the commands described above are used to orchestrate the download and execution of malicious DLL files."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "cmd" and ProcessCommandLine contains "/c") and (ProcessCommandLine contains " curl" or ProcessCommandLine contains " wget" or ProcessCommandLine contains " timeout " or ProcessCommandLine contains " ping ") and (ProcessCommandLine contains " rundll32" or ProcessCommandLine contains " mkdir ") and (ProcessCommandLine contains " & " or ProcessCommandLine contains " || ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl", "Execution"]
  techniques                 = ["T1059", "T1105", "T1218"]
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