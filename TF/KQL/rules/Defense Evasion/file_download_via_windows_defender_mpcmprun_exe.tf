resource "azurerm_sentinel_alert_rule_scheduled" "file_download_via_windows_defender_mpcmprun_exe" {
  name                       = "file_download_via_windows_defender_mpcmprun_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download Via Windows Defender MpCmpRun.EXE"
  description                = "Detects the use of Windows Defender MpCmdRun.EXE to download files"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "DownloadFile" and ProcessCommandLine contains "url") and (ProcessVersionInfoOriginalFileName =~ "MpCmdRun.exe" or FolderPath endswith "\\MpCmdRun.exe" or ProcessCommandLine contains "MpCmdRun.exe" or ProcessVersionInfoFileDescription =~ "Microsoft Malware Protection Command Line Utility")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1218", "T1105"]
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