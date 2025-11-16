resource "azurerm_sentinel_alert_rule_scheduled" "system_shutdown_reboot_macos" {
  name                       = "system_shutdown_reboot_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Shutdown/Reboot - MacOs"
  description                = "Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. - Legitimate administrative activity"
  severity                   = "Informational"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/shutdown" or FolderPath endswith "/reboot" or FolderPath endswith "/halt"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1529"]
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