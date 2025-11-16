resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_anydesk_incoming_connection" {
  name                       = "remote_access_tool_anydesk_incoming_connection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - AnyDesk Incoming Connection"
  description                = "Detects incoming connections to AnyDesk. This could indicate a potential remote attacker trying to connect to a listening instance of AnyDesk and use it as potential command and control channel. - Legitimate incoming connections (e.g. sysadmin activity). Most of the time I would expect outgoing connections (initiated locally)."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\AnyDesk.exe" or InitiatingProcessFolderPath endswith "\\AnyDeskMSI.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "CommandAndControl"]
  techniques                 = ["T1219"]
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
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }
}