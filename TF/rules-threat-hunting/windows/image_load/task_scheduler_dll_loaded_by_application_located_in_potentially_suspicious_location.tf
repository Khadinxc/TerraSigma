resource "azurerm_sentinel_alert_rule_scheduled" "task_scheduler_dll_loaded_by_application_located_in_potentially_suspicious_location" {
  name                       = "task_scheduler_dll_loaded_by_application_located_in_potentially_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Task Scheduler DLL Loaded By Application Located In Potentially Suspicious Location"
  description                = "Detects the loading of the \"taskschd.dll\" module from a process that located in a potentially suspicious or uncommon directory. The loading of this DLL might indicate that the application have the capability to create a scheduled task via the \"Schedule.Service\" COM object. Investigation of the loading application and its behavior is required to determining if its malicious. - Some installers might generate false positives, apply additional filters accordingly."
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\taskschd.dll" or InitiatingProcessVersionInfoOriginalFileName =~ "taskschd.dll") and (InitiatingProcessFolderPath contains ":\\Temp\\" or InitiatingProcessFolderPath contains ":\\Users\\Public\\" or InitiatingProcessFolderPath contains ":\\Windows\\Temp\\" or InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" or InitiatingProcessFolderPath contains "\\Desktop\\" or InitiatingProcessFolderPath contains "\\Downloads\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Execution", "PrivilegeEscalation"]
  techniques                 = ["T1053"]
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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