resource "azurerm_sentinel_alert_rule_scheduled" "credui_dll_loaded_by_uncommon_process" {
  name                       = "credui_dll_loaded_by_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "CredUI.DLL Loaded By Uncommon Process"
  description                = "Detects loading of \"credui.dll\" and related DLLs by an uncommon process. Attackers might leverage this DLL for potential use of \"CredUIPromptForCredentials\" or \"CredUnPackAuthenticationBufferW\". - Other legitimate processes loading those DLLs in your environment."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where ((FolderPath endswith "\\credui.dll" or FolderPath endswith "\\wincredui.dll") or (InitiatingProcessVersionInfoOriginalFileName in~ ("credui.dll", "wincredui.dll"))) and (not(((InitiatingProcessFolderPath in~ ("C:\\Windows\\explorer.exe", "C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe", "C:\\Windows\\regedit.exe")) or (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\")))) and (not(((InitiatingProcessFolderPath contains "\\AppData\\Local\\Microsoft\\OneDrive\\" and InitiatingProcessFolderPath startswith "C:\\Users\\") or InitiatingProcessFolderPath endswith "\\opera_autoupdate.exe" or (InitiatingProcessFolderPath endswith "\\procexp64.exe" or InitiatingProcessFolderPath endswith "\\procexp.exe") or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Microsoft\\Teams\\" and InitiatingProcessFolderPath endswith "\\Teams.exe" and InitiatingProcessFolderPath startswith "C:\\Users\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "Collection"]
  techniques                 = ["T1056"]
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