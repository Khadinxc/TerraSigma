resource "azurerm_sentinel_alert_rule_scheduled" "pnscan_binary_data_transmission_activity" {
  name                       = "pnscan_binary_data_transmission_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Pnscan Binary Data Transmission Activity"
  description                = "Detects command line patterns associated with the use of Pnscan for sending and receiving binary data across the network. This behavior has been identified in a Linux malware campaign targeting Docker, Apache Hadoop, Redis, and Confluence and was previously used by the threat actor known as TeamTNT"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine matches regex "-(W|R)\\s?(\\s|"|')([0-9a-fA-F]{2}\\s?){2,20}(\\s|"|')"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1046"]
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