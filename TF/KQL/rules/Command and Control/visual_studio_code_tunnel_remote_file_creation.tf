resource "azurerm_sentinel_alert_rule_scheduled" "visual_studio_code_tunnel_remote_file_creation" {
  name                       = "visual_studio_code_tunnel_remote_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Visual Studio Code Tunnel Remote File Creation"
  description                = "Detects the creation of file by the \"node.exe\" process in the \".vscode-server\" directory. Could be a sign of remote file creation via VsCode tunnel feature"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath contains "\\servers\\Stable-" and InitiatingProcessFolderPath endswith "\\server\\node.exe" and FolderPath contains "\\.vscode-server\\data\\User\\History\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
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