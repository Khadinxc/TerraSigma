resource "azurerm_sentinel_alert_rule_scheduled" "renamed_jusched_exe_execution" {
  name                       = "renamed_jusched_exe_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed Jusched.EXE Execution"
  description                = "Detects the execution of a renamed \"jusched.exe\" as seen used by the cobalt group"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoFileDescription in~ ("Java Update Scheduler", "Java(TM) Update Scheduler")) and (not(FolderPath endswith "\\jusched.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1036"]
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