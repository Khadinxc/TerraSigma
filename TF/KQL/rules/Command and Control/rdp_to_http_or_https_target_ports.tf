resource "azurerm_sentinel_alert_rule_scheduled" "rdp_to_http_or_https_target_ports" {
  name                       = "rdp_to_http_or_https_target_ports"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "RDP to HTTP or HTTPS Target Ports"
  description                = "Detects svchost hosting RDP termsvcs communicating to target systems on TCP port 80 or 443"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemotePort in~ ("80", "443")) and InitiatingProcessFolderPath endswith "\\svchost.exe" and LocalPort == 3389
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "LateralMovement"]
  techniques                 = ["T1572", "T1021"]
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