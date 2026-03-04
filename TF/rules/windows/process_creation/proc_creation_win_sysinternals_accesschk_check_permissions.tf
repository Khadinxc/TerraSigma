resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_sysinternals_accesschk_check_permissions" {
  name                       = "proc_creation_win_sysinternals_accesschk_check_permissions"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Permission Check Via Accesschk.EXE"
  description                = "Detects the usage of the \"Accesschk\" utility, an access and privilege audit tool developed by SysInternal and often being abused by attacker to verify process privileges Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_accesschk_check_permissions.yml - System administrator Usage | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_accesschk_check_permissions.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "uwcqv " or ProcessCommandLine contains "kwsu " or ProcessCommandLine contains "qwsu " or ProcessCommandLine contains "uwdqs ") and (ProcessVersionInfoProductName endswith "AccessChk" or ProcessVersionInfoFileDescription contains "Reports effective permissions" or (FolderPath endswith "\\accesschk.exe" or FolderPath endswith "\\accesschk64.exe") or ProcessVersionInfoOriginalFileName =~ "accesschk.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1069"]
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