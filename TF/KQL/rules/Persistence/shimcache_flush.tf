resource "azurerm_sentinel_alert_rule_scheduled" "shimcache_flush" {
  name                       = "shimcache_flush"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ShimCache Flush"
  description                = "Detects actions that clear the local ShimCache and remove forensic evidence"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "rundll32" and ProcessCommandLine contains "apphelp.dll") and (ProcessCommandLine contains "ShimFlushCache" or ProcessCommandLine contains "#250")) or ((ProcessCommandLine contains "rundll32" and ProcessCommandLine contains "kernel32.dll") and (ProcessCommandLine contains "BaseFlushAppcompatCache" or ProcessCommandLine contains "#46"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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