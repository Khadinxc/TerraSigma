resource "azurerm_sentinel_alert_rule_scheduled" "hijack_legit_rdp_session_to_move_laterally" {
  name                       = "hijack_legit_rdp_session_to_move_laterally"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Hijack Legit RDP Session to Move Laterally"
  description                = "Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\mstsc.exe" and FolderPath contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
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