resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_desktopimgdownldr_target_file" {
  name                       = "suspicious_desktopimgdownldr_target_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Desktopimgdownldr Target File"
  description                = "Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\svchost.exe" and FolderPath contains "\\Personalization\\LockScreenImage\\") and (not(FolderPath contains "C:\\Windows\\")) and (not((FolderPath contains ".jpg" or FolderPath contains ".jpeg" or FolderPath contains ".png")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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