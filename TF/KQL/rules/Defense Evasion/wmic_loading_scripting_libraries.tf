resource "azurerm_sentinel_alert_rule_scheduled" "wmic_loading_scripting_libraries" {
  name                       = "wmic_loading_scripting_libraries"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WMIC Loading Scripting Libraries"
  description                = "Detects threat actors proxy executing code and bypassing application controls by leveraging wmic and the `/FORMAT` argument switch to download and execute an XSL file (i.e js, vbs, etc). - The command wmic os get lastboottuptime loads vbscript.dll - The command wmic os get locale loads vbscript.dll - Since the ImageLoad event doesn't have enough information in this case. It's better to look at the recent process creation events that spawned the WMIC process and investigate the command line and parent/child processes to get more insights"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\jscript.dll" or FolderPath endswith "\\vbscript.dll") and InitiatingProcessFolderPath endswith "\\wmic.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1220"]
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