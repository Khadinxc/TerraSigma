resource "azurerm_sentinel_alert_rule_scheduled" "microsoft_excel_add_in_loaded" {
  name                       = "microsoft_excel_add_in_loaded"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Microsoft Excel Add-In Loaded"
  description                = "Detects Microsoft Excel loading an Add-In (.xll) file - The rules is only looking for \".xll\" loads. So some false positives are expected with legitimate and allowed XLLs"
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith ".xll" and InitiatingProcessFolderPath endswith "\\excel.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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