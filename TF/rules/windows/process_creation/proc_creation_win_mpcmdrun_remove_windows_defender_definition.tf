resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_mpcmdrun_remove_windows_defender_definition" {
  name                       = "proc_creation_win_mpcmdrun_remove_windows_defender_definition"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Defender Definition Files Removed"
  description                = "Adversaries may disable security tools to avoid possible detection of their tools and activities by removing Windows Defender Definition Files Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mpcmdrun_remove_windows_defender_definition.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mpcmdrun_remove_windows_defender_definition.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -RemoveDefinitions" and ProcessCommandLine contains " -All") and (FolderPath endswith "\\MpCmdRun.exe" or ProcessVersionInfoOriginalFileName =~ "MpCmdRun.exe")
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