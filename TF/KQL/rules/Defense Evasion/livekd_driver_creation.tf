resource "azurerm_sentinel_alert_rule_scheduled" "livekd_driver_creation" {
  name                       = "livekd_driver_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LiveKD Driver Creation"
  description                = "Detects the creation of the LiveKD driver, which is used for live kernel debugging - Legitimate usage of LiveKD for debugging purposes will also trigger this"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\livekd.exe" or InitiatingProcessFolderPath endswith "\\livek64.exe") and FolderPath =~ "C:\\Windows\\System32\\drivers\\LiveKdD.SYS"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
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