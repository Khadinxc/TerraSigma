resource "azurerm_sentinel_alert_rule_scheduled" "image_load_dll_rstrtmgr_uncommon_load" {
  name                       = "image_load_dll_rstrtmgr_uncommon_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Load Of RstrtMgr.DLL By An Uncommon Process"
  description                = "Detects the load of RstrtMgr DLL (Restart Manager) by an uncommon process. This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows. It could also be used for anti-analysis purposes by shut downing specific processes. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_dll_rstrtmgr_uncommon_load.yml - Other legitimate Windows processes not currently listed - Processes related to software installation | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_dll_rstrtmgr_uncommon_load.yml"
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\RstrtMgr.dll" or InitiatingProcessVersionInfoOriginalFileName =~ "RstrtMgr.dll") and (not((InitiatingProcessFolderPath startswith "C:\\Windows\\Temp\\'" or (InitiatingProcessFolderPath startswith "C:\\$WINDOWS.~BT\\'" or InitiatingProcessFolderPath startswith "C:\\$WinREAgent\\'" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\'" or InitiatingProcessFolderPath startswith "C:\\Program Files\\'" or InitiatingProcessFolderPath startswith "C:\\ProgramData\\'" or InitiatingProcessFolderPath startswith "C:\\Windows\\explorer.exe'" or InitiatingProcessFolderPath startswith "C:\\Windows\\SoftwareDistribution\\'" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysNative\\'" or InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\'" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\'" or InitiatingProcessFolderPath startswith "C:\\Windows\\WinSxS\\'" or InitiatingProcessFolderPath startswith "C:\\WUDownloadCache\\'") or ((InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\is-" and InitiatingProcessFolderPath contains ".tmp\\") and InitiatingProcessFolderPath endswith ".tmp" and InitiatingProcessFolderPath startswith "C:\\Users\\'")))) and (not((InitiatingProcessFolderPath endswith "\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe" and InitiatingProcessFolderPath startswith "C:\\Users\\")))
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
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