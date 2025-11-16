resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_grpconv_execution" {
  name                       = "suspicious_grpconv_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious GrpConv Execution"
  description                = "Detects the suspicious execution of a utility to convert Windows 3.x .grp files or for persistence purposes by malicious software or actors"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "grpconv.exe -o" or ProcessCommandLine contains "grpconv -o"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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