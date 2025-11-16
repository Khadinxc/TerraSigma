resource "azurerm_sentinel_alert_rule_scheduled" "potential_conti_ransomware_activity" {
  name                       = "potential_conti_ransomware_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Conti Ransomware Activity"
  description                = "Detects a specific command used by the Conti ransomware group - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "-m " and ProcessCommandLine contains "-net " and ProcessCommandLine contains "-size " and ProcessCommandLine contains "-nomutex " and ProcessCommandLine contains "-p \\\\" and ProcessCommandLine contains "$"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1486"]
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