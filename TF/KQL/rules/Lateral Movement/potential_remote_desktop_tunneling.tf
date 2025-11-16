resource "azurerm_sentinel_alert_rule_scheduled" "potential_remote_desktop_tunneling" {
  name                       = "potential_remote_desktop_tunneling"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Remote Desktop Tunneling"
  description                = "Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains ":3389" and (ProcessCommandLine contains " -L " or ProcessCommandLine contains " -P " or ProcessCommandLine contains " -R " or ProcessCommandLine contains " -pw " or ProcessCommandLine contains " -ssh ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement"]
  techniques                 = ["T1021"]
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