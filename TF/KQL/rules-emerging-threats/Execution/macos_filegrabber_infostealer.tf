resource "azurerm_sentinel_alert_rule_scheduled" "macos_filegrabber_infostealer" {
  name                       = "macos_filegrabber_infostealer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "MacOS FileGrabber Infostealer"
  description                = "Detects execution of FileGrabber on macOS, which is associated with Amos infostealer campaigns targeting sensitive user files."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "FileGrabber" and ProcessCommandLine contains "/tmp"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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