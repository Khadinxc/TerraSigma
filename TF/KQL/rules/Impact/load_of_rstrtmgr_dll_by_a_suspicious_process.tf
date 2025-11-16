resource "azurerm_sentinel_alert_rule_scheduled" "load_of_rstrtmgr_dll_by_a_suspicious_process" {
  name                       = "load_of_rstrtmgr_dll_by_a_suspicious_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Load Of RstrtMgr.DLL By A Suspicious Process"
  description                = "Detects the load of RstrtMgr DLL (Restart Manager) by a suspicious process. This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows. It could also be used for anti-analysis purposes by shut downing specific processes. - Processes related to software installation"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\RstrtMgr.dll" or InitiatingProcessVersionInfoOriginalFileName =~ "RstrtMgr.dll") and ((InitiatingProcessFolderPath contains ":\\Perflogs\\" or InitiatingProcessFolderPath contains ":\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\Temporary Internet") or ((InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Favorites\\") or (InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Favourites\\") or (InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Contacts\\")))
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