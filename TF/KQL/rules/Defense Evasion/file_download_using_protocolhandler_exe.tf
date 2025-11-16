resource "azurerm_sentinel_alert_rule_scheduled" "file_download_using_protocolhandler_exe" {
  name                       = "file_download_using_protocolhandler_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download Using ProtocolHandler.exe"
  description                = "Detects usage of \"ProtocolHandler\" to download files. Downloaded files will be located in the cache folder (for example - %LOCALAPPDATA%\\Microsoft\\Windows\\INetCache\\IE)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "ftp://" or ProcessCommandLine contains "http://" or ProcessCommandLine contains "https://") and (FolderPath endswith "\\protocolhandler.exe" or ProcessVersionInfoOriginalFileName =~ "ProtocolHandler.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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