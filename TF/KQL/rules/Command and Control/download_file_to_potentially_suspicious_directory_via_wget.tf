resource "azurerm_sentinel_alert_rule_scheduled" "download_file_to_potentially_suspicious_directory_via_wget" {
  name                       = "download_file_to_potentially_suspicious_directory_via_wget"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Download File To Potentially Suspicious Directory Via Wget"
  description                = "Detects the use of wget to download content to a suspicious directory"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/wget" and (ProcessCommandLine matches regex "\\s-O\\s" or ProcessCommandLine contains "--output-document") and ProcessCommandLine contains "/tmp/"
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