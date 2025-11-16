resource "azurerm_sentinel_alert_rule_scheduled" "system_network_connections_discovery_linux" {
  name                       = "system_network_connections_discovery_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Network Connections Discovery - Linux"
  description                = "Detects usage of system utilities to discover system network connections - Legitimate activities"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "/who" or FolderPath endswith "/w" or FolderPath endswith "/last" or FolderPath endswith "/lsof" or FolderPath endswith "/netstat") and (not((FolderPath endswith "/who" and InitiatingProcessCommandLine contains "/usr/bin/landscape-sysinfo")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1049"]
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
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}