resource "azurerm_sentinel_alert_rule_scheduled" "jxa_in_memory_execution_via_osascript" {
  name                       = "jxa_in_memory_execution_via_osascript"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "JXA In-memory Execution Via OSAScript"
  description                = "Detects possible malicious execution of JXA in-memory via OSAScript"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -l " and ProcessCommandLine contains "JavaScript") or ProcessCommandLine contains ".js") and (ProcessCommandLine contains "osascript" and ProcessCommandLine contains " -e " and ProcessCommandLine contains "eval" and ProcessCommandLine contains "NSData.dataWithContentsOfURL")
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