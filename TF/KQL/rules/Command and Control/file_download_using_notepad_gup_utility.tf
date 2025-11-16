resource "azurerm_sentinel_alert_rule_scheduled" "file_download_using_notepad_gup_utility" {
  name                       = "file_download_using_notepad_gup_utility"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download Using Notepad++ GUP Utility"
  description                = "Detects execution of the Notepad++ updater (gup) from a process other than Notepad++ to download files. - Other parent processes other than notepad++ using GUP that are not currently identified"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -unzipTo " and ProcessCommandLine contains "http") and (FolderPath endswith "\\GUP.exe" or ProcessVersionInfoOriginalFileName =~ "gup.exe")) and (not(InitiatingProcessFolderPath endswith "\\notepad++.exe"))
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}