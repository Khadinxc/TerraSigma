resource "azurerm_sentinel_alert_rule_scheduled" "file_deletion" {
  name                       = "file_deletion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Deletion"
  description                = "Detects file deletion using \"rm\", \"shred\" or \"unlink\" commands which are used often by adversaries to delete files left behind by the actions of their intrusion activity - Legitimate administration activities"
  severity                   = "Informational"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/rm" or FolderPath endswith "/shred" or FolderPath endswith "/unlink"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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