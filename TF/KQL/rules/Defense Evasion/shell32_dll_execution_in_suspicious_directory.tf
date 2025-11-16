resource "azurerm_sentinel_alert_rule_scheduled" "shell32_dll_execution_in_suspicious_directory" {
  name                       = "shell32_dll_execution_in_suspicious_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shell32 DLL Execution in Suspicious Directory"
  description                = "Detects shell32.dll executing a DLL in a suspicious directory"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "%AppData%" or ProcessCommandLine contains "%LocalAppData%" or ProcessCommandLine contains "%Temp%" or ProcessCommandLine contains "%tmp%" or ProcessCommandLine contains "\\AppData\\" or ProcessCommandLine contains "\\Temp\\" or ProcessCommandLine contains "\\Users\\Public\\") and (ProcessCommandLine contains "shell32.dll" and ProcessCommandLine contains "Control_RunDLL")) and (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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