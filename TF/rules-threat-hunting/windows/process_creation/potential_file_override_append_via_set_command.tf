resource "azurerm_sentinel_alert_rule_scheduled" "potential_file_override_append_via_set_command" {
  name                       = "potential_file_override_append_via_set_command"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential File Override/Append Via SET Command"
  description                = "Detects the use of the \"SET\" internal command of Cmd.EXE with the /p flag followed directly by an \"=\" sign. Attackers used this technique along with an append redirection operator \">>\" in order to update the content of a file indirectly. Ex: cmd /c >> example.txt set /p=\"test data\". This will append \"test data\" to contents of \"example.txt\". The typical use case of the \"set /p=\" command is to prompt the user for input. - Legitimate use of the SET with the \"/p\" flag for user prompting. command in administrative scripts or user-generated scripts."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/c set /p=" or ProcessCommandLine contains "\"set /p=" or (ProcessCommandLine contains ">>" and ProcessCommandLine contains "set /p=")) and (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
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