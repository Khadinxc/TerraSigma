resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_creation_activity_from_fake_recycle_bin_folder" {
  name                       = "suspicious_file_creation_activity_from_fake_recycle_bin_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Creation Activity From Fake Recycle.Bin Folder"
  description                = "Detects file write event from/to a fake recycle bin folder that is often used as a staging directory for malware"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath contains "RECYCLERS.BIN\\" or InitiatingProcessFolderPath contains "RECYCLER.BIN\\") or (FolderPath contains "RECYCLERS.BIN\\" or FolderPath contains "RECYCLER.BIN\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
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