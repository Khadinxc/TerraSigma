resource "azurerm_sentinel_alert_rule_scheduled" "vscode_code_tunnel_execution_file_indicator" {
  name                       = "vscode_code_tunnel_execution_file_indicator"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "VsCode Code Tunnel Execution File Indicator"
  description                = "Detects the creation of a file with the name \"code_tunnel.json\" which indicate execution and usage of VsCode tunneling utility. Attackers can abuse this functionality to establish a C2 channel - Legitimate usage of VsCode tunneling functionality will also trigger this"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\code_tunnel.json"
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