resource "azurerm_sentinel_alert_rule_scheduled" "access_to_windows_outlook_mail_files_by_uncommon_applications" {
  name                       = "access_to_windows_outlook_mail_files_by_uncommon_applications"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access To Windows Outlook Mail Files By Uncommon Applications"
  description                = "Detects file access requests to Windows Outlook Mail by uncommon processes. Could indicate potential attempt of credential stealing. Requires heavy baselining before usage - Antivirus, Anti-Spyware, Anti-Malware Software - Backup software - Legitimate software installed on partitions other than \"C:\\\" - Searching software such as \"everything.exe\""
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where (FileName contains "\\AppData\\Local\\Comms\\Unistore\\data" or FileName endswith "\\AppData\\Local\\Comms\\UnistoreDB\\store.vol") and (not(((InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\system32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\") or InitiatingProcessFolderPath =~ "System"))) and (not((((InitiatingProcessFolderPath endswith "\\MpCopyAccelerator.exe" or InitiatingProcessFolderPath endswith "\\MsMpEng.exe") and InitiatingProcessFolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\") or (InitiatingProcessFolderPath endswith "\\thor64.exe" or InitiatingProcessFolderPath endswith "\\thor.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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