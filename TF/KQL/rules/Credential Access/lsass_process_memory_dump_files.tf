resource "azurerm_sentinel_alert_rule_scheduled" "lsass_process_memory_dump_files" {
  name                       = "lsass_process_memory_dump_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LSASS Process Memory Dump Files"
  description                = "Detects creation of files with names used by different memory dumping tools to create a memory dump of the LSASS process memory, which contains user credentials."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "\\Andrew.dmp" or FolderPath endswith "\\Coredump.dmp" or FolderPath endswith "\\lsass.dmp" or FolderPath endswith "\\lsass.rar" or FolderPath endswith "\\lsass.zip" or FolderPath endswith "\\NotLSASS.zip" or FolderPath endswith "\\PPLBlade.dmp" or FolderPath endswith "\\rustive.dmp") or (FolderPath contains "\\lsass_2" or FolderPath contains "\\lsassdmp" or FolderPath contains "\\lsassdump") or (FolderPath contains "\\lsass" and FolderPath contains ".dmp") or (FolderPath contains "SQLDmpr" and FolderPath endswith ".mdmp") or ((FolderPath contains "\\nanodump" or FolderPath contains "\\proc_") and FolderPath endswith ".dmp")
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