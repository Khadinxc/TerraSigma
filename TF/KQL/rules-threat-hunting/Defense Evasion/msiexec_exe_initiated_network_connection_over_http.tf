resource "azurerm_sentinel_alert_rule_scheduled" "msiexec_exe_initiated_network_connection_over_http" {
  name                       = "msiexec_exe_initiated_network_connection_over_http"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Msiexec.EXE Initiated Network Connection Over HTTP"
  description                = "Detects a network connection initiated by an \"Msiexec.exe\" process over port 80 or 443. Adversaries might abuse \"msiexec.exe\" to install and execute remotely hosted packages. Use this rule to hunt for potentially anomalous or suspicious communications. - Likely"
  severity                   = "Low"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemotePort in~ ("80", "443")) and InitiatingProcessFolderPath endswith "\\msiexec.exe"
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