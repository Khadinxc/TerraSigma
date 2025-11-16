resource "azurerm_sentinel_alert_rule_scheduled" "wusa_exe_executed_by_parent_process_located_in_suspicious_location" {
  name                       = "wusa_exe_executed_by_parent_process_located_in_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wusa.EXE Executed By Parent Process Located In Suspicious Location"
  description                = "Detects execution of the \"wusa.exe\" (Windows Update Standalone Installer) utility by a parent process that is located in a suspicious location. Attackers could instantiate an instance of \"wusa.exe\" in order to bypass User Account Control (UAC). They can duplicate the access token from \"wusa.exe\" to gain elevated privileges."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\wusa.exe" and ((InitiatingProcessFolderPath contains ":\\Perflogs\\" or InitiatingProcessFolderPath contains ":\\Users\\Public\\" or InitiatingProcessFolderPath contains ":\\Windows\\Temp\\" or InitiatingProcessFolderPath contains "\\Appdata\\Local\\Temp\\" or InitiatingProcessFolderPath contains "\\Temporary Internet") or ((InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Favorites\\") or (InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Favourites\\") or (InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Contacts\\") or (InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Pictures\\"))) and (not(ProcessCommandLine contains ".msu"))
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