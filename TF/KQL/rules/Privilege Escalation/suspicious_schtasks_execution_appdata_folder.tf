resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_schtasks_execution_appdata_folder" {
  name                       = "suspicious_schtasks_execution_appdata_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Schtasks Execution AppData Folder"
  description                = "Detects the creation of a schtask that executes a file from C:\\Users\\<USER>\\AppData\\Local"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "NT AUT" or ProcessCommandLine contains " SYSTEM ") and (ProcessCommandLine contains "/Create" and ProcessCommandLine contains "/RU" and ProcessCommandLine contains "/TR" and ProcessCommandLine contains "C:\\Users\\" and ProcessCommandLine contains "\\AppData\\Local\\") and FolderPath endswith "\\schtasks.exe") and (not((ProcessCommandLine contains "/TN TVInstallRestore" and FolderPath endswith "\\schtasks.exe" and (InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" and InitiatingProcessFolderPath contains "TeamViewer_.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053", "T1059"]
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