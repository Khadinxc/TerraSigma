resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_compression_tool_parameters" {
  name                       = "potentially_suspicious_compression_tool_parameters"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Compression Tool Parameters"
  description                = "Detects potentially suspicious command line arguments of common data compression tools"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -p" or ProcessCommandLine contains " -ta" or ProcessCommandLine contains " -tb" or ProcessCommandLine contains " -sdel" or ProcessCommandLine contains " -dw" or ProcessCommandLine contains " -hp") and ((ProcessVersionInfoOriginalFileName contains "7z" and ProcessVersionInfoOriginalFileName contains ".exe") or ProcessVersionInfoOriginalFileName endswith "rar.exe" or (ProcessVersionInfoOriginalFileName contains "Command" and ProcessVersionInfoOriginalFileName contains "Line" and ProcessVersionInfoOriginalFileName contains "RAR"))) and (not((InitiatingProcessFolderPath contains ":\\Program Files\\" or InitiatingProcessFolderPath contains ":\\Program Files (x86)\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1560"]
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