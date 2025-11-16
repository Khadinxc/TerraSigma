resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_network_command" {
  name                       = "suspicious_network_command"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Network Command"
  description                = "Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems - Administrator, hotline ask to user"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine matches regex "ipconfig\\s+/all" or ProcessCommandLine matches regex "netsh\\s+interface show interface" or ProcessCommandLine matches regex "arp\\s+-a" or ProcessCommandLine matches regex "nbtstat\\s+-n" or ProcessCommandLine matches regex "net\\s+config" or ProcessCommandLine matches regex "route\\s+print"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1016"]
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