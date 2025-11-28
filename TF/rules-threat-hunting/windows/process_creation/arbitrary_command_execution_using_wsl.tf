resource "azurerm_sentinel_alert_rule_scheduled" "arbitrary_command_execution_using_wsl" {
  name                       = "arbitrary_command_execution_using_wsl"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Arbitrary Command Execution Using WSL"
  description                = "Detects potential abuse of Windows Subsystem for Linux (WSL) binary as a Living of the Land binary in order to execute arbitrary Linux or Windows commands. - Automation and orchestration scripts may use this method to execute scripts etc. - Legitimate use by Windows to kill processes opened via WSL (example VsCode WSL server)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -e " or ProcessCommandLine contains " --exec" or ProcessCommandLine contains " --system" or ProcessCommandLine contains " --shell-type " or ProcessCommandLine contains " /mnt/c" or ProcessCommandLine contains " --user root" or ProcessCommandLine contains " -u root" or ProcessCommandLine contains "--debug-shell") and (FolderPath endswith "\\wsl.exe" or ProcessVersionInfoOriginalFileName =~ "wsl.exe")) and (not(((ProcessCommandLine contains " -d " and ProcessCommandLine contains " -e kill ") and InitiatingProcessFolderPath endswith "\\cmd.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1218", "T1202"]
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