resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_rurat_execution_from_unusual_location" {
  name                       = "remote_access_tool_rurat_execution_from_unusual_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - RURAT Execution From Unusual Location"
  description                = "Detects execution of Remote Utilities RAT (RURAT) from an unusual location (outside of 'C:\\Program Files')"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\rutserv.exe" or FolderPath endswith "\\rfusclient.exe") or ProcessVersionInfoProductName =~ "Remote Utilities") and (not((FolderPath startswith "C:\\Program Files\\Remote Utilities" or FolderPath startswith "C:\\Program Files (x86)\\Remote Utilities")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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