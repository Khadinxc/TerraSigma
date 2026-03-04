resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_susp_task_write" {
  name                       = "file_event_win_susp_task_write"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Scheduled Task Write to System32 Tasks"
  description                = "Detects the creation of tasks from processes executed from suspicious locations Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_task_write.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_task_write.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath contains "\\AppData\\" or InitiatingProcessFolderPath contains "C:\\PerfLogs" or InitiatingProcessFolderPath contains "\\Windows\\System32\\config\\systemprofile") and FolderPath contains "\\Windows\\System32\\Tasks"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "Execution"]
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