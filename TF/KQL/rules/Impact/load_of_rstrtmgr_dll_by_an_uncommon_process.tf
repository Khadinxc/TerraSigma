resource "azurerm_sentinel_alert_rule_scheduled" "load_of_rstrtmgr_dll_by_an_uncommon_process" {
  name                       = "load_of_rstrtmgr_dll_by_an_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Load Of RstrtMgr.DLL By An Uncommon Process"
  description                = "Detects the load of RstrtMgr DLL (Restart Manager) by an uncommon process. This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows. It could also be used for anti-analysis purposes by shut downing specific processes. - Other legitimate Windows processes not currently listed - Processes related to software installation"
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\RstrtMgr.dll" or InitiatingProcessVersionInfoOriginalFileName =~ "RstrtMgr.dll") and (not((InitiatingProcessFolderPath contains ":\\Windows\\Temp\\" or (InitiatingProcessFolderPath contains ":\\$WINDOWS.~BT\\" or InitiatingProcessFolderPath contains ":\\$WinREAgent\\" or InitiatingProcessFolderPath contains ":\\Program Files (x86)\\" or InitiatingProcessFolderPath contains ":\\Program Files\\" or InitiatingProcessFolderPath contains ":\\ProgramData\\" or InitiatingProcessFolderPath contains ":\\Windows\\explorer.exe" or InitiatingProcessFolderPath contains ":\\Windows\\SoftwareDistribution\\" or InitiatingProcessFolderPath contains ":\\Windows\\SysNative\\" or InitiatingProcessFolderPath contains ":\\Windows\\System32\\" or InitiatingProcessFolderPath contains ":\\Windows\\SysWOW64\\" or InitiatingProcessFolderPath contains ":\\Windows\\WinSxS\\" or InitiatingProcessFolderPath contains ":\\WUDownloadCache\\") or ((InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\is-" and InitiatingProcessFolderPath contains ".tmp\\") and InitiatingProcessFolderPath endswith ".tmp"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact", "DefenseEvasion"]
  techniques                 = ["T1486", "T1562"]
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