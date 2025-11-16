resource "azurerm_sentinel_alert_rule_scheduled" "mint_sandstorm_log4j_wstomcat_process_execution" {
  name                       = "mint_sandstorm_log4j_wstomcat_process_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Mint Sandstorm - Log4J Wstomcat Process Execution"
  description                = "Detects Log4J Wstomcat process execution as seen in Mint Sandstorm activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\ws_tomcatservice.exe" and (not(FolderPath endswith "\\repadmin.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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