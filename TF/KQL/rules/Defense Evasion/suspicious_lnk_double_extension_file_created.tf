resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_lnk_double_extension_file_created" {
  name                       = "suspicious_lnk_double_extension_file_created"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious LNK Double Extension File Created"
  description                = "Detects the creation of files with an \"LNK\" as a second extension. This is sometimes used by malware as a method to abuse the fact that Windows hides the \"LNK\" extension by default. - Some tuning is required for other general purpose directories of third party apps"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where ((FolderPath contains ".doc." or FolderPath contains ".docx." or FolderPath contains ".jpg." or FolderPath contains ".pdf." or FolderPath contains ".ppt." or FolderPath contains ".pptx." or FolderPath contains ".xls." or FolderPath contains ".xlsx.") and FolderPath endswith ".lnk") and (not(FolderPath contains "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\")) and (not(((InitiatingProcessFolderPath endswith "\\excel.exe" and FolderPath contains "\\AppData\\Roaming\\Microsoft\\Excel") or (InitiatingProcessFolderPath endswith "\\powerpnt.exe" and FolderPath contains "\\AppData\\Roaming\\Microsoft\\PowerPoint") or ((InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\winword.exe") and FolderPath contains "\\AppData\\Roaming\\Microsoft\\Office\\Recent\\") or (InitiatingProcessFolderPath endswith "\\winword.exe" and FolderPath contains "\\AppData\\Roaming\\Microsoft\\Word"))))
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