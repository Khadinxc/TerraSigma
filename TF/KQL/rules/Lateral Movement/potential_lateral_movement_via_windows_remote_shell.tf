resource "azurerm_sentinel_alert_rule_scheduled" "potential_lateral_movement_via_windows_remote_shell" {
  name                       = "potential_lateral_movement_via_windows_remote_shell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Lateral Movement via Windows Remote Shell"
  description                = "Detects a child process spawned by 'winrshost.exe', which suggests remote command execution through Windows Remote Shell (WinRs) and may indicate potential lateral movement activity. - Legitimate use of WinRM within the organization"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\winrshost.exe" and (not(FolderPath =~ "C:\\Windows\\System32\\conhost.exe"))
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