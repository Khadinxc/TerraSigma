resource "azurerm_sentinel_alert_rule_scheduled" "renamed_remote_utilities_rat_rurat_execution" {
  name                       = "renamed_remote_utilities_rat_rurat_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed Remote Utilities RAT (RURAT) Execution"
  description                = "Detects execution of renamed Remote Utilities (RURAT) via Product PE header field"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoProductName =~ "Remote Utilities" and (not((FolderPath endswith "\\rutserv.exe" or FolderPath endswith "\\rfusclient.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Collection", "CommandAndControl", "Discovery"]
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