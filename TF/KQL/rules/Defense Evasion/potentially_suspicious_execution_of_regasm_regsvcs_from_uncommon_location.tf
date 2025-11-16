resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_execution_of_regasm_regsvcs_from_uncommon_location" {
  name                       = "potentially_suspicious_execution_of_regasm_regsvcs_from_uncommon_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Location"
  description                = "Detects potentially suspicious execution of the Regasm/Regsvcs utilities from a potentially suspicious location"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" or ProcessCommandLine contains "\\PerfLogs\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\Windows\\Temp\\") and ((FolderPath endswith "\\Regsvcs.exe" or FolderPath endswith "\\Regasm.exe") or (ProcessVersionInfoOriginalFileName in~ ("RegSvcs.exe", "RegAsm.exe")))
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