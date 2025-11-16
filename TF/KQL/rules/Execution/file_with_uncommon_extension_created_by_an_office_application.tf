resource "azurerm_sentinel_alert_rule_scheduled" "file_with_uncommon_extension_created_by_an_office_application" {
  name                       = "file_with_uncommon_extension_created_by_an_office_application"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File With Uncommon Extension Created By An Office Application"
  description                = "Detects the creation of files with an executable or script extension by an Office application."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\msaccess.exe" or InitiatingProcessFolderPath endswith "\\mspub.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\visio.exe" or InitiatingProcessFolderPath endswith "\\winword.exe") and (FolderPath endswith ".bat" or FolderPath endswith ".cmd" or FolderPath endswith ".com" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".ocx" or FolderPath endswith ".proj" or FolderPath endswith ".ps1" or FolderPath endswith ".scf" or FolderPath endswith ".scr" or FolderPath endswith ".sys" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs" or FolderPath endswith ".wsf" or FolderPath endswith ".wsh")) and (not((FolderPath contains "\\AppData\\Local\\assembly\\tmp\\" and FolderPath endswith ".dll"))) and (not((((FolderPath contains "C:\\Users\\" and FolderPath contains "\\AppData\\Local\\Microsoft\\Office\\" and FolderPath contains "\\BackstageInAppNavCache\\") and FolderPath endswith ".com") or (InitiatingProcessFolderPath endswith "\\winword.exe" and FolderPath contains "\\AppData\\Local\\Temp\\webexdelta\\" and (FolderPath endswith ".dll" or FolderPath endswith ".exe")) or ((FolderPath contains "C:\\Users\\" and FolderPath contains "\\AppData\\Local\\Microsoft\\Office\\" and FolderPath contains "\\WebServiceCache\\AllUsers") and FolderPath endswith ".com"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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