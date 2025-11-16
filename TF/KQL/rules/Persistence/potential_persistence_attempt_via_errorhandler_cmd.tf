resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_attempt_via_errorhandler_cmd" {
  name                       = "potential_persistence_attempt_via_errorhandler_cmd"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Attempt Via ErrorHandler.Cmd"
  description                = "Detects creation of a file named \"ErrorHandler.cmd\" in the \"C:\\WINDOWS\\Setup\\Scripts\\\" directory which could be used as a method of persistence The content of C:\\WINDOWS\\Setup\\Scripts\\ErrorHandler.cmd is read whenever some tools under C:\\WINDOWS\\System32\\oobe\\ (e.g. Setup.exe) fail to run for any reason."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\WINDOWS\\Setup\\Scripts\\ErrorHandler.cmd"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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