resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_child_process_of_aspnetcompiler" {
  name                       = "suspicious_child_process_of_aspnetcompiler"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Child Process of AspNetCompiler"
  description                = "Detects potentially suspicious child processes of \"aspnet_compiler.exe\"."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\calc.exe" or FolderPath endswith "\\notepad.exe") or (FolderPath contains "\\Users\\Public\\" or FolderPath contains "\\AppData\\Local\\Temp\\" or FolderPath contains "\\AppData\\Local\\Roaming\\" or FolderPath contains ":\\Temp\\" or FolderPath contains ":\\Windows\\Temp\\" or FolderPath contains ":\\Windows\\System32\\Tasks\\" or FolderPath contains ":\\Windows\\Tasks\\")) and InitiatingProcessFolderPath endswith "\\aspnet_compiler.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1127"]
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