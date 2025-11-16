resource "azurerm_sentinel_alert_rule_scheduled" "lsass_process_memory_dump_creation_via_taskmgr_exe" {
  name                       = "lsass_process_memory_dump_creation_via_taskmgr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LSASS Process Memory Dump Creation Via Taskmgr.EXE"
  description                = "Detects the creation of an \"lsass.dmp\" file by the taskmgr process. This indicates a manual dumping of the LSASS.exe process memory using Windows Task Manager. - Rare case of troubleshooting by an administrator or support that has to be investigated regardless"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith ":\\Windows\\system32\\taskmgr.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\SysWOW64\\taskmgr.exe") and (FolderPath contains "\\AppData\\Local\\Temp\\" and FolderPath contains "\\lsass" and FolderPath contains ".DMP")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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