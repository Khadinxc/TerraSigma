resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_office_spawn_exe_from_users_directory" {
  name                       = "proc_creation_win_office_spawn_exe_from_users_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Binary In User Directory Spawned From Office Application"
  description                = <<DESC
    Detects an executable in the users directory started from one of the Microsoft Office suite applications (Word, Excel, PowerPoint, Publisher, Visio)

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_spawn_exe_from_users_directory.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith ".exe" and FolderPath startswith "C:\\users\\" and (InitiatingProcessFolderPath endswith "\\WINWORD.EXE" or InitiatingProcessFolderPath endswith "\\EXCEL.EXE" or InitiatingProcessFolderPath endswith "\\POWERPNT.exe" or InitiatingProcessFolderPath endswith "\\MSPUB.exe" or InitiatingProcessFolderPath endswith "\\VISIO.exe" or InitiatingProcessFolderPath endswith "\\MSACCESS.exe" or InitiatingProcessFolderPath endswith "\\EQNEDT32.exe")) and (not(FolderPath endswith "\\Teams.exe"))
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