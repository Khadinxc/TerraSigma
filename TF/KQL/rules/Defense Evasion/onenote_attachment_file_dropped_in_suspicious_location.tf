resource "azurerm_sentinel_alert_rule_scheduled" "onenote_attachment_file_dropped_in_suspicious_location" {
  name                       = "onenote_attachment_file_dropped_in_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OneNote Attachment File Dropped In Suspicious Location"
  description                = "Detects creation of files with the \".one\"/\".onepkg\" extension in suspicious or uncommon locations. This could be a sign of attackers abusing OneNote attachments - Legitimate usage of \".one\" or \".onepkg\" files from those locations"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where ((FolderPath contains "\\AppData\\Local\\Temp\\" or FolderPath contains "\\Users\\Public\\" or FolderPath contains "\\Windows\\Temp\\" or FolderPath contains ":\\Temp\\") and (FolderPath endswith ".one" or FolderPath endswith ".onepkg")) and (not((InitiatingProcessFolderPath contains ":\\Program Files\\Microsoft Office\\" and InitiatingProcessFolderPath endswith "\\ONENOTE.EXE")))
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