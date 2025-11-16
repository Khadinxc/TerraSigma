resource "azurerm_sentinel_alert_rule_scheduled" "clipboard_data_collection_via_osascript" {
  name                       = "clipboard_data_collection_via_osascript"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Clipboard Data Collection Via OSAScript"
  description                = "Detects possible collection of data from the clipboard via execution of the osascript binary - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "osascript" and ProcessCommandLine contains " -e " and ProcessCommandLine contains "clipboard"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "Execution"]
  techniques                 = ["T1115", "T1059"]
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
  }
}