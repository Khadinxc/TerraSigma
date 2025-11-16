resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_creation_in_uncommon_appdata_folder" {
  name                       = "suspicious_file_creation_in_uncommon_appdata_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Creation In Uncommon AppData Folder"
  description                = "Detects the creation of suspicious files and folders inside the user's AppData folder but not inside any of the common and well known directories (Local, Romaing, LocalLow). This method could be used as a method to bypass detection who exclude the AppData folder in fear of FPs - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\AppData\\" and (FolderPath endswith ".bat" or FolderPath endswith ".cmd" or FolderPath endswith ".cpl" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".iso" or FolderPath endswith ".lnk" or FolderPath endswith ".msi" or FolderPath endswith ".ps1" or FolderPath endswith ".psm1" or FolderPath endswith ".scr" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs") and FolderPath startswith "C:\\Users\\") and (not(((FolderPath contains "\\AppData\\Local\\" or FolderPath contains "\\AppData\\LocalLow\\" or FolderPath contains "\\AppData\\Roaming\\") and FolderPath startswith "C:\\Users\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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