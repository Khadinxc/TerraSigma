resource "azurerm_sentinel_alert_rule_scheduled" "monitoring_for_persistence_via_bits" {
  name                       = "monitoring_for_persistence_via_bits"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Monitoring For Persistence Via BITS"
  description                = "BITS will allow you to schedule a command to execute after a successful download to notify you that the job is finished. When the job runs on the system the command specified in the BITS job will be executed. This can be abused by actors to create a backdoor within the system and for persistence. It will be chained in a BITS job to schedule the download of malware/additional binaries and execute the program after being downloaded."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\bitsadmin.exe" or ProcessVersionInfoOriginalFileName =~ "bitsadmin.exe") and ((ProcessCommandLine contains "/SetNotifyCmdLine" and (ProcessCommandLine contains "%COMSPEC%" or ProcessCommandLine contains "cmd.exe" or ProcessCommandLine contains "regsvr32.exe")) or (ProcessCommandLine contains "/Addfile" and (ProcessCommandLine contains "http:" or ProcessCommandLine contains "https:" or ProcessCommandLine contains "ftp:" or ProcessCommandLine contains "ftps:")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1197"]
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
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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