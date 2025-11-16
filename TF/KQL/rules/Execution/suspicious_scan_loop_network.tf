resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_scan_loop_network" {
  name                       = "suspicious_scan_loop_network"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Scan Loop Network"
  description                = "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system - Legitimate script"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "for " or ProcessCommandLine contains "foreach ") and (ProcessCommandLine contains "nslookup" or ProcessCommandLine contains "ping")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Discovery"]
  techniques                 = ["T1059", "T1018"]
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