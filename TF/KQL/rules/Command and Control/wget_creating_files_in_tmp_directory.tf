resource "azurerm_sentinel_alert_rule_scheduled" "wget_creating_files_in_tmp_directory" {
  name                       = "wget_creating_files_in_tmp_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wget Creating Files in Tmp Directory"
  description                = "Detects the use of wget to download content in a temporary directory such as \"/tmp\" or \"/var/tmp\" - Legitimate downloads of files in the tmp folder."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "/wget" and (FolderPath startswith "/tmp/" or FolderPath startswith "/var/tmp/")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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