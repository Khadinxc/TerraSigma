resource "azurerm_sentinel_alert_rule_scheduled" "potential_goopdate_dll_sideloading" {
  name                       = "potential_goopdate_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Goopdate.DLL Sideloading"
  description                = "Detects potential DLL sideloading of \"goopdate.dll\", a DLL used by googleupdate.exe - Other third party chromium browsers located in AppData"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\goopdate.dll" and (not((FolderPath startswith "C:\\Program Files (x86)\\" or FolderPath startswith "C:\\Program Files\\"))) and (not((((FolderPath contains "\\AppData\\Local\\Temp\\GUM" and FolderPath contains ".tmp\\goopdate.dll") and (InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\GUM" and InitiatingProcessFolderPath contains ".tmp\\Dropbox")) or ((FolderPath contains "\\AppData\\Local\\Temp\\GUM" or FolderPath contains ":\\Windows\\SystemTemp\\GUM") and (InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\GUM" or InitiatingProcessFolderPath contains ":\\Windows\\SystemTemp\\GUM") and InitiatingProcessFolderPath endswith ".tmp\\GoogleUpdate.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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