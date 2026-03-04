resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_desktop_ini_created_by_uncommon_process" {
  name                       = "file_event_win_desktop_ini_created_by_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Desktop.INI Created by Uncommon Process"
  description                = "Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_desktop_ini_created_by_uncommon_process.yml - Operations performed through Windows SCCM or equivalent - Read only access list authority | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_desktop_ini_created_by_uncommon_process.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\desktop.ini" and (not(((InitiatingProcessFolderPath startswith "C:\\Windows\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\") or FolderPath startswith "C:\\$WINDOWS.~BT\\NewOS\\"))) and (not(((InitiatingProcessFolderPath endswith "\\AppData\\Local\\JetBrains\\Toolbox\\bin\\7z.exe" and InitiatingProcessFolderPath startswith "C:\\Users\\" and FolderPath contains "\\JetBrains\\apps\\") or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Microsoft\\OneDrive\\" and InitiatingProcessFolderPath startswith "C:\\Users\\"))))
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}