resource "azurerm_sentinel_alert_rule_scheduled" "drop_binaries_into_spool_drivers_color_folder" {
  name                       = "drop_binaries_into_spool_drivers_color_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Drop Binaries Into Spool Drivers Color Folder"
  description                = "Detects the creation of suspcious binary files inside the \"\\windows\\system32\\spool\\drivers\\color\\\" as seen in the blog referenced below"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".sys") and FolderPath startswith "C:\\Windows\\System32\\spool\\drivers\\color\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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