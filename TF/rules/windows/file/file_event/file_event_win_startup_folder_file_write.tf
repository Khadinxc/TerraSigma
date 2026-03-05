resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_startup_folder_file_write" {
  name                       = "file_event_win_startup_folder_file_write"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Startup Folder File Write"
  description                = <<DESC
    A General detection for files being created in the Windows startup directory. This could be an indicator of persistence.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_startup_folder_file_write.yml

    False Positives:
    - FP could be caused by legitimate application writing shortcuts for example. This folder should always be inspected to make sure that all the files in there are legitimate
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp" and (not(((InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\wuauclt.exe", "C:\\Windows\\uus\\ARM64\\wuaucltcore.exe")) or (FolderPath startswith "C:\\$WINDOWS.~BT\\NewOS\\" or FolderPath startswith "C:\\$WinREAgent\\Scratch\\Mount\\")))) and (not((InitiatingProcessFolderPath endswith "\\ONENOTE.EXE" and FolderPath endswith "\\Send to OneNote.lnk")))
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