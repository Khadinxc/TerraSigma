resource "azurerm_sentinel_alert_rule_scheduled" "new_run_key_pointing_to_suspicious_folder" {
  name                       = "new_run_key_pointing_to_suspicious_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New RUN Key Pointing to Suspicious Folder"
  description                = "Detects suspicious new RUN key element pointing to an executable in a suspicious folder - Software using weird folders for updates"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" or RegistryKey contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") and ((RegistryValueData contains ":\\Perflogs" or RegistryValueData contains ":\\ProgramData'" or RegistryValueData contains ":\\Windows\\Temp" or RegistryValueData contains ":\\Temp" or RegistryValueData contains "\\AppData\\Local\\Temp" or RegistryValueData contains "\\AppData\\Roaming" or RegistryValueData contains ":\\$Recycle.bin" or RegistryValueData contains ":\\Users\\Default" or RegistryValueData contains ":\\Users\\public" or RegistryValueData contains "%temp%" or RegistryValueData contains "%tmp%" or RegistryValueData contains "%Public%" or RegistryValueData contains "%AppData%") or (RegistryValueData contains ":\\Users\\" and (RegistryValueData contains "\\Favorites" or RegistryValueData contains "\\Favourites" or RegistryValueData contains "\\Contacts" or RegistryValueData contains "\\Music" or RegistryValueData contains "\\Pictures" or RegistryValueData contains "\\Documents" or RegistryValueData contains "\\Photos"))) and (not(((RegistryValueData contains "\\AppData\\Local\\Temp\\" or RegistryValueData contains "C:\\Windows\\Temp\\") and (RegistryValueData contains "rundll32.exe " and RegistryValueData contains "C:\\WINDOWS\\system32\\advpack.dll,DelNodeRunDLL32") and InitiatingProcessFolderPath startswith "C:\\Windows\\SoftwareDistribution\\Download\\" and RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\RunOnce*"))) and (not((RegistryValueData endswith "Spotify.exe --autostart --minimized" and (InitiatingProcessFolderPath endswith "C:\\Program Files\\Spotify\\Spotify.exe" or InitiatingProcessFolderPath endswith "C:\\Program Files (x86)\\Spotify\\Spotify.exe" or InitiatingProcessFolderPath endswith "\\AppData\\Roaming\\Spotify\\Spotify.exe") and RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Spotify")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}