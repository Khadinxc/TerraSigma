resource "azurerm_sentinel_alert_rule_scheduled" "file_or_folder_permissions_modifications" {
  name                       = "file_or_folder_permissions_modifications"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File or Folder Permissions Modifications"
  description                = "Detects a file or folder's permissions being modified or tampered with. - Users interacting with the files on their own (unlikely unless privileged users). - Dynatrace app"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains "/grant" or ProcessCommandLine contains "/setowner" or ProcessCommandLine contains "/inheritance:r") and (FolderPath endswith "\\cacls.exe" or FolderPath endswith "\\icacls.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe")) or (ProcessCommandLine contains "-r" and FolderPath endswith "\\attrib.exe") or FolderPath endswith "\\takeown.exe") and (not(((ProcessCommandLine contains ":\\Program Files (x86)\\Avira" or ProcessCommandLine contains ":\\Program Files\\Avira") or ProcessCommandLine endswith "ICACLS C:\\ProgramData\\dynatrace\\gateway\\config\\connectivity.history /reset" or (ProcessCommandLine contains "ICACLS C:\\ProgramData\\dynatrace\\gateway\\config\\config.properties /grant :r " and ProcessCommandLine contains "S-1-5-19:F") or (ProcessCommandLine contains "\\AppData\\Local\\Programs\\Microsoft VS Code" or ProcessCommandLine contains ":\\Program Files\\Microsoft VS Code"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1222"]
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