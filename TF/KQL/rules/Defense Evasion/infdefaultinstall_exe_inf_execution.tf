resource "azurerm_sentinel_alert_rule_scheduled" "infdefaultinstall_exe_inf_execution" {
  name                       = "infdefaultinstall_exe_inf_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "InfDefaultInstall.exe .inf Execution"
  description                = "Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "InfDefaultInstall.exe " and ProcessCommandLine contains ".inf"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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