resource "azurerm_sentinel_alert_rule_scheduled" "default_rdp_port_changed_to_non_standard_port" {
  name                       = "default_rdp_port_changed_to_non_standard_port"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Default RDP Port Changed to Non Standard Port"
  description                = "Detects changes to the default RDP port. Remote desktop is a common feature in operating systems. It allows a user to log into a remote system using an interactive session with a graphical user interface. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS)."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber" and (not(RegistryValueData =~ "DWORD (0x00000d3d)"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}