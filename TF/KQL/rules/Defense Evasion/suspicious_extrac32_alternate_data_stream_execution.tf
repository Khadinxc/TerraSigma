resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_extrac32_alternate_data_stream_execution" {
  name                       = "suspicious_extrac32_alternate_data_stream_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Extrac32 Alternate Data Stream Execution"
  description                = "Extract data from cab file and hide it in an alternate data stream"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "extrac32.exe" and ProcessCommandLine contains ".cab") and ProcessCommandLine matches regex ":[^\\\\]"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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