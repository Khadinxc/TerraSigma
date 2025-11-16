resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_hh_exe_execution" {
  name                       = "suspicious_hh_exe_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious HH.EXE Execution"
  description                = "Detects a suspicious execution of a Microsoft HTML Help (HH.exe)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoOriginalFileName =~ "HH.exe" or FolderPath endswith "\\hh.exe") and (ProcessCommandLine contains ".application" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\Content.Outlook\\" or ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\Windows\\Temp\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution", "InitialAccess"]
  techniques                 = ["T1047", "T1059", "T1218", "T1566"]
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