resource "azurerm_sentinel_alert_rule_scheduled" "windows_backup_deleted_via_wbadmin_exe" {
  name                       = "windows_backup_deleted_via_wbadmin_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Backup Deleted Via Wbadmin.EXE"
  description                = "Detects the deletion of backups or system state backups via \"wbadmin.exe\". This technique is used by numerous ransomware families and actors. This may only be successful on server platforms that have Windows Backup enabled. - Legitimate backup activity from administration scripts and software."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "delete " and ProcessCommandLine contains "backup") and (FolderPath endswith "\\wbadmin.exe" or ProcessVersionInfoOriginalFileName =~ "WBADMIN.EXE")) and (not(ProcessCommandLine contains "keepVersions:0"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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