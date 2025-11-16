resource "azurerm_sentinel_alert_rule_scheduled" "potential_amsi_bypass_using_null_bits" {
  name                       = "potential_amsi_bypass_using_null_bits"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential AMSI Bypass Using NULL Bits"
  description                = "Detects usage of special strings/null bits in order to potentially bypass AMSI functionalities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "if(0){{{0}}}' -f $(0 -as [char]) +" or ProcessCommandLine contains "#<NULL>"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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