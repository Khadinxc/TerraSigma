resource "azurerm_sentinel_alert_rule_scheduled" "system_network_discovery_linux" {
  name                       = "system_network_discovery_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Network Discovery - Linux"
  description                = "Detects enumeration of local network configuration - Legitimate administration activities"
  severity                   = "Informational"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "/etc/resolv.conf" or (FolderPath endswith "/firewall-cmd" or FolderPath endswith "/ufw" or FolderPath endswith "/iptables" or FolderPath endswith "/netstat" or FolderPath endswith "/ss" or FolderPath endswith "/ip" or FolderPath endswith "/ifconfig" or FolderPath endswith "/systemd-resolve" or FolderPath endswith "/route")
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