resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_taskmgr_susp_child_process" {
  name                       = "proc_creation_win_taskmgr_susp_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Process Created Via Taskmgr.EXE"
  description                = <<DESC
    Detects the creation of a process via the Windows task manager. This might be an attempt to bypass UAC

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_taskmgr_susp_child_process.yml

    False Positives:
    - Administrative activity
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\taskmgr.exe" and (not((FolderPath endswith ":\\Windows\\System32\\mmc.exe" or FolderPath endswith ":\\Windows\\System32\\resmon.exe" or FolderPath endswith ":\\Windows\\System32\\Taskmgr.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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