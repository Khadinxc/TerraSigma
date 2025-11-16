resource "azurerm_sentinel_alert_rule_scheduled" "register_app_vbs_proxy_execution" {
  name                       = "register_app_vbs_proxy_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "REGISTER_APP.VBS Proxy Execution"
  description                = "Detects the use of a Microsoft signed script 'REGISTER_APP.VBS' to register a VSS/VDS Provider as a COM+ application. - Legitimate usage of the script. Always investigate what's being registered to confirm if it's benign"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\register_app.vbs" and ProcessCommandLine contains "-register"
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