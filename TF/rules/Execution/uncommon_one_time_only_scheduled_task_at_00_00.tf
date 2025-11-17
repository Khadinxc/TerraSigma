resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_one_time_only_scheduled_task_at_00_00" {
  name                       = "uncommon_one_time_only_scheduled_task_at_00_00"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon One Time Only Scheduled Task At 00:00"
  description                = "Detects scheduled task creation events that include suspicious actions, and is run once at 00:00 - Software installation"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "wscript" or ProcessCommandLine contains "vbscript" or ProcessCommandLine contains "cscript" or ProcessCommandLine contains "wmic " or ProcessCommandLine contains "wmic.exe" or ProcessCommandLine contains "regsvr32.exe" or ProcessCommandLine contains "powershell" or ProcessCommandLine contains "\\AppData\\") and (FolderPath contains "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe") and (ProcessCommandLine contains "once" and ProcessCommandLine contains "00:00")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1053"]
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