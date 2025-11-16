resource "azurerm_sentinel_alert_rule_scheduled" "tunneling_tool_execution" {
  name                       = "tunneling_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Tunneling Tool Execution"
  description                = "Detects the execution of well known tools that can be abused for data exfiltration and tunneling. - Legitimate administrators using one of these tools"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\httptunnel.exe" or FolderPath endswith "\\plink.exe" or FolderPath endswith "\\socat.exe" or FolderPath endswith "\\stunnel.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration", "CommandAndControl"]
  techniques                 = ["T1041", "T1572", "T1071"]
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