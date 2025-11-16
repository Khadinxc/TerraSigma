resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_mstsc_exe_execution_with_local_rdp_file" {
  name                       = "suspicious_mstsc_exe_execution_with_local_rdp_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Mstsc.EXE Execution With Local RDP File"
  description                = "Detects potential RDP connection via Mstsc using a local \".rdp\" file located in suspicious locations. - Likelihood is related to how often the paths are used in the environment"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith ".rdp" or ProcessCommandLine endswith ".rdp\"") and (FolderPath endswith "\\mstsc.exe" or ProcessVersionInfoOriginalFileName =~ "mstsc.exe") and (ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\System32\\spool\\drivers\\color" or ProcessCommandLine contains ":\\Windows\\System32\\Tasks_Migrated " or ProcessCommandLine contains ":\\Windows\\Tasks\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains ":\\Windows\\Tracing\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\Downloads\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]
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