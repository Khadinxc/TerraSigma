resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_double_extension_files" {
  name                       = "suspicious_double_extension_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Double Extension Files"
  description                = "Detects dropped files with double extensions, which is often used by malware as a method to abuse the fact that Windows hide default extensions by default. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith ".rar.exe" or FolderPath endswith ".zip.exe") or ((FolderPath contains ".doc." or FolderPath contains ".docx." or FolderPath contains ".gif." or FolderPath contains ".jpeg." or FolderPath contains ".jpg." or FolderPath contains ".mp3." or FolderPath contains ".mp4." or FolderPath contains ".pdf." or FolderPath contains ".png." or FolderPath contains ".ppt." or FolderPath contains ".pptx." or FolderPath contains ".rtf." or FolderPath contains ".svg." or FolderPath contains ".txt." or FolderPath contains ".xls." or FolderPath contains ".xlsx.") and (FolderPath endswith ".exe" or FolderPath endswith ".iso" or FolderPath endswith ".rar" or FolderPath endswith ".svg" or FolderPath endswith ".zip"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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