resource "azurerm_sentinel_alert_rule_scheduled" "startup_item_file_created_macos" {
  name                       = "startup_item_file_created_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Startup Item File Created - MacOS"
  description                = "Detects the creation of a startup item plist file, that automatically get executed at boot initialization to establish persistence. Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items. - Legitimate administration activities"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".plist" and (FolderPath startswith "/Library/StartupItems/" or FolderPath startswith "/System/Library/StartupItems")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1037"]
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