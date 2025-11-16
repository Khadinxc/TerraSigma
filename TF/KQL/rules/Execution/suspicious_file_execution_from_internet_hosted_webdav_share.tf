resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_execution_from_internet_hosted_webdav_share" {
  name                       = "suspicious_file_execution_from_internet_hosted_webdav_share"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Execution From Internet Hosted WebDav Share"
  description                = "Detects the execution of the \"net use\" command to mount a WebDAV server and then immediately execute some content in it. As seen being used in malicious LNK files"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " net use http" and ProcessCommandLine contains "& start /b " and ProcessCommandLine contains "\\DavWWWRoot\\") and (ProcessCommandLine contains ".exe " or ProcessCommandLine contains ".dll " or ProcessCommandLine contains ".bat " or ProcessCommandLine contains ".vbs " or ProcessCommandLine contains ".ps1 ") and (FolderPath contains "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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