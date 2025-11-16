resource "azurerm_sentinel_alert_rule_scheduled" "terminate_linux_process_via_kill" {
  name                       = "terminate_linux_process_via_kill"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Terminate Linux Process Via Kill"
  description                = "Detects usage of command line tools such as \"kill\", \"pkill\" or \"killall\" to terminate or signal a running process."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/kill" or FolderPath endswith "/killall" or FolderPath endswith "/pkill" or FolderPath endswith "/xkill"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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