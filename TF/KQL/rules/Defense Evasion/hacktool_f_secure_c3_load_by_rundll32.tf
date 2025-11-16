resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_f_secure_c3_load_by_rundll32" {
  name                       = "hacktool_f_secure_c3_load_by_rundll32"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - F-Secure C3 Load by Rundll32"
  description                = "F-Secure C3 produces DLLs with a default exported StartNodeRelay function."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "rundll32.exe" and ProcessCommandLine contains ".dll" and ProcessCommandLine contains "StartNodeRelay"
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