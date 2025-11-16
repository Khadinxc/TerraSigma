resource "azurerm_sentinel_alert_rule_scheduled" "potential_suspicious_registry_file_imported_via_reg_exe" {
  name                       = "potential_suspicious_registry_file_imported_via_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious Registry File Imported Via Reg.EXE"
  description                = "Detects the import of '.reg' files from suspicious paths using the 'reg.exe' utility - Legitimate import of keys"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " import " and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe") and (ProcessCommandLine contains "C:\\Users\\" or ProcessCommandLine contains "%temp%" or ProcessCommandLine contains "%tmp%" or ProcessCommandLine contains "%appdata%" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "C:\\Windows\\Temp\\" or ProcessCommandLine contains "C:\\ProgramData\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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