resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_via_notepad_exe" {
  name                       = "network_connection_initiated_via_notepad_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated Via Notepad.EXE"
  description                = "Detects a network connection that is initiated by the \"notepad.exe\" process. This might be a sign of process injection from a beacon process or something similar. Notepad rarely initiates a network communication except when printing documents for example. - Printing documents via notepad might cause communication with the printer via port 9100 or similar."
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\notepad.exe" and (not(RemotePort == 9100))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "CommandAndControl", "Execution", "DefenseEvasion"]
  techniques                 = ["T1055"]
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