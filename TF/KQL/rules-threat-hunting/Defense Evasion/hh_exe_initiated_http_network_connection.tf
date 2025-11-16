resource "azurerm_sentinel_alert_rule_scheduled" "hh_exe_initiated_http_network_connection" {
  name                       = "hh_exe_initiated_http_network_connection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HH.EXE Initiated HTTP Network Connection"
  description                = "Detects a network connection initiated by the \"hh.exe\" process to HTTP destination ports, which could indicate the execution/download of remotely hosted .chm files."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemotePort in~ ("80", "443")) and InitiatingProcessFolderPath endswith "\\hh.exe"
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
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }
}