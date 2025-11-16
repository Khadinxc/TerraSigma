resource "azurerm_sentinel_alert_rule_scheduled" "potential_download_upload_activity_using_type_command" {
  name                       = "potential_download_upload_activity_using_type_command"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Download/Upload Activity Using Type Command"
  description                = "Detects usage of the \"type\" command to download/upload data from WebDAV server"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "type \\\\" and ProcessCommandLine contains " > ") or (ProcessCommandLine contains "type " and ProcessCommandLine contains " > \\\\")
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
  }
}