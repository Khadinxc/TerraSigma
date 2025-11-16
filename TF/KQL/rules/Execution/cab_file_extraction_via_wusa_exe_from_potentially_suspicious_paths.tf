resource "azurerm_sentinel_alert_rule_scheduled" "cab_file_extraction_via_wusa_exe_from_potentially_suspicious_paths" {
  name                       = "cab_file_extraction_via_wusa_exe_from_potentially_suspicious_paths"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths"
  description                = "Detects the execution of the \"wusa.exe\" (Windows Update Standalone Installer) utility to extract \".cab\" files using the \"/extract\" argument from potentially suspicious paths."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ":\\PerfLogs\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\Appdata\\Local\\Temp\\") and (ProcessCommandLine contains "/extract:" and FolderPath endswith "\\wusa.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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