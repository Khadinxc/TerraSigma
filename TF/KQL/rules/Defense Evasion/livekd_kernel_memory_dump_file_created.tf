resource "azurerm_sentinel_alert_rule_scheduled" "livekd_kernel_memory_dump_file_created" {
  name                       = "livekd_kernel_memory_dump_file_created"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LiveKD Kernel Memory Dump File Created"
  description                = "Detects the creation of a file that has the same name as the default LiveKD kernel memory dump. - In rare occasions administrators might leverage LiveKD to perform live kernel debugging. This should not be allowed on production systems. Investigate and apply additional filters where necessary."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath =~ "C:\\Windows\\livekd.dmp"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
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