resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_by_imewdbld_exe" {
  name                       = "network_connection_initiated_by_imewdbld_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated By IMEWDBLD.EXE"
  description                = "Detects a network connection initiated by IMEWDBLD.EXE. This might indicate potential abuse of the utility as a LOLBIN in order to download arbitrary files or additional payloads."
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\IMEWDBLD.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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