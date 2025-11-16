resource "azurerm_sentinel_alert_rule_scheduled" "time_machine_backup_disabled_via_tmutil_macos" {
  name                       = "time_machine_backup_disabled_via_tmutil_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Time Machine Backup Disabled Via Tmutil - MacOS"
  description                = "Detects disabling of Time Machine (Apple's automated backup utility software) via the native macOS backup utility \"tmutil\". An attacker can use this to prevent backups from occurring. - Legitimate administrator activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "disable" and (FolderPath endswith "/tmutil" or ProcessCommandLine contains "tmutil")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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