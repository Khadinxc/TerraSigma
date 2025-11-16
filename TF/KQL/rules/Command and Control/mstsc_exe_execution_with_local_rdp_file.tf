resource "azurerm_sentinel_alert_rule_scheduled" "mstsc_exe_execution_with_local_rdp_file" {
  name                       = "mstsc_exe_execution_with_local_rdp_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Mstsc.EXE Execution With Local RDP File"
  description                = "Detects potential RDP connection via Mstsc using a local \".rdp\" file - Likely with legitimate usage of \".rdp\" files"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine endswith ".rdp" or ProcessCommandLine endswith ".rdp\"") and (FolderPath endswith "\\mstsc.exe" or ProcessVersionInfoOriginalFileName =~ "mstsc.exe")) and (not((ProcessCommandLine contains "C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\lxss\\wslhost.exe")))
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