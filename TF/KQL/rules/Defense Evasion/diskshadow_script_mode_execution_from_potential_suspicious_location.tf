resource "azurerm_sentinel_alert_rule_scheduled" "diskshadow_script_mode_execution_from_potential_suspicious_location" {
  name                       = "diskshadow_script_mode_execution_from_potential_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Diskshadow Script Mode - Execution From Potential Suspicious Location"
  description                = "Detects execution of \"Diskshadow.exe\" in script mode using the \"/s\" flag where the script is located in a potentially suspicious location."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-s " or ProcessCommandLine contains "/s " or ProcessCommandLine contains "–s " or ProcessCommandLine contains "—s " or ProcessCommandLine contains "―s ") and (ProcessVersionInfoOriginalFileName =~ "diskshadow.exe" or FolderPath endswith "\\diskshadow.exe") and (ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\AppData\\Local\\" or ProcessCommandLine contains "\\AppData\\Roaming\\" or ProcessCommandLine contains "\\ProgramData\\" or ProcessCommandLine contains "\\Users\\Public\\")
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