resource "azurerm_sentinel_alert_rule_scheduled" "potential_process_execution_proxy_via_cl_invocation_ps1" {
  name                       = "potential_process_execution_proxy_via_cl_invocation_ps1"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Process Execution Proxy Via CL_Invocation.ps1"
  description                = "Detects calls to \"SyncInvoke\" that is part of the \"CL_Invocation.ps1\" script to proxy execution using \"System.Diagnostics.Process\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "SyncInvoke "
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1216"]
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