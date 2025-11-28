resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task_creation_via_schtasks_exe" {
  name                       = "scheduled_task_creation_via_schtasks_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scheduled Task Creation Via Schtasks.EXE"
  description                = "Detects the creation of scheduled tasks by user accounts via the \"schtasks\" utility. - Administrative activity - Software installation"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " /create " and FolderPath endswith "\\schtasks.exe") and (not((AccountName contains "AUTHORI" or AccountName contains "AUTORI"))) and (not((ProcessCommandLine contains "Microsoft\\Office\\Office Performance Monitor" and (FolderPath in~ ("C:\\Windows\\System32\\schtasks.exe", "C:\\Windows\\SysWOW64\\schtasks.exe")) and (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Microsoft Office\\root\\integration\\integrator.exe", "C:\\Program Files (x86)\\Microsoft Office\\root\\integration\\integrator.exe")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence", "PrivilegeEscalation"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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