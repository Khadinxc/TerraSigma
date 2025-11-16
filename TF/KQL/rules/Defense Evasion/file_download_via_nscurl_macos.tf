resource "azurerm_sentinel_alert_rule_scheduled" "file_download_via_nscurl_macos" {
  name                       = "file_download_via_nscurl_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download Via Nscurl - MacOS"
  description                = "Detects the execution of the nscurl utility in order to download files. - Legitimate usage of nscurl by administrators and users."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "--download " or ProcessCommandLine contains "--download-directory " or ProcessCommandLine contains "--output " or ProcessCommandLine contains "-dir " or ProcessCommandLine contains "-dl " or ProcessCommandLine contains "-ld" or ProcessCommandLine contains "-o ") and FolderPath endswith "/nscurl"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl"]
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