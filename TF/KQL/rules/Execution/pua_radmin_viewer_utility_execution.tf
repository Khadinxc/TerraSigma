resource "azurerm_sentinel_alert_rule_scheduled" "pua_radmin_viewer_utility_execution" {
  name                       = "pua_radmin_viewer_utility_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Radmin Viewer Utility Execution"
  description                = "Detects the execution of Radmin which can be abused by an adversary to remotely control Windows machines"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoFileDescription =~ "Radmin Viewer" or ProcessVersionInfoProductName =~ "Radmin Viewer" or ProcessVersionInfoOriginalFileName =~ "Radmin.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement"]
  techniques                 = ["T1072"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
  }
}