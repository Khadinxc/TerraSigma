resource "azurerm_sentinel_alert_rule_scheduled" "java_running_with_remote_debugging" {
  name                       = "java_running_with_remote_debugging"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Java Running with Remote Debugging"
  description                = "Detects a JAVA process running with remote debugging allowing more than just localhost to connect"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "transport=dt_socket,address=" and (ProcessCommandLine contains "jre1." or ProcessCommandLine contains "jdk1.")) and (not((ProcessCommandLine contains "address=127.0.0.1" or ProcessCommandLine contains "address=localhost")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1203"]
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