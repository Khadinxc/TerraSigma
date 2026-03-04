resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_office_onenote_files_in_susp_locations" {
  name                       = "file_event_win_office_onenote_files_in_susp_locations"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OneNote Attachment File Dropped In Suspicious Location"
  description                = "Detects creation of files with the \".one\"/\".onepkg\" extension in suspicious or uncommon locations. This could be a sign of attackers abusing OneNote attachments Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_office_onenote_files_in_susp_locations.yml - Legitimate usage of \".one\" or \".onepkg\" files from those locations | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_office_onenote_files_in_susp_locations.yml"
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
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