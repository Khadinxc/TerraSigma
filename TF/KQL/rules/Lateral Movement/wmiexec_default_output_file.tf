resource "azurerm_sentinel_alert_rule_scheduled" "wmiexec_default_output_file" {
  name                       = "wmiexec_default_output_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wmiexec Default Output File"
  description                = "Detects the creation of the default output filename used by the wmiexec tool - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath matches regex "\\\\Windows\\\\__1\\d{9}\\.\\d{1,7}$" or FolderPath matches regex "C:\\\\__1\\d{9}\\.\\d{1,7}$" or FolderPath matches regex "D:\\\\__1\\d{9}\\.\\d{1,7}$"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement", "Execution"]
  techniques                 = ["T1047"]
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