resource "azurerm_sentinel_alert_rule_scheduled" "potential_conti_ransomware_database_dumping_activity_via_sqlcmd" {
  name                       = "potential_conti_ransomware_database_dumping_activity_via_sqlcmd"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Conti Ransomware Database Dumping Activity Via SQLCmd"
  description                = "Detects a command used by conti to dump database"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "sys.sysprocesses" or ProcessCommandLine contains "master.dbo.sysdatabases" or ProcessCommandLine contains "BACKUP DATABASE") and ProcessCommandLine contains " -S localhost " and (FolderPath endswith "\\sqlcmd.exe" or (ProcessCommandLine contains "sqlcmd " or ProcessCommandLine contains "sqlcmd.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1005"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}