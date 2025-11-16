resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_wordpad_outbound_connections" {
  name                       = "suspicious_wordpad_outbound_connections"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Wordpad Outbound Connections"
  description                = "Detects a network connection initiated by \"wordpad.exe\" over uncommon destination ports. This might indicate potential process injection activity from a beacon or similar mechanisms. - Other ports can be used, apply additional filters accordingly"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\wordpad.exe" and (not((RemotePort in~ ("80", "139", "443", "445", "465", "587", "993", "995"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl"]
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