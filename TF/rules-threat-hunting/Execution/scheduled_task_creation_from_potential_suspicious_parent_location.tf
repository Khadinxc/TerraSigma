resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task_creation_from_potential_suspicious_parent_location" {
  name                       = "scheduled_task_creation_from_potential_suspicious_parent_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scheduled Task Creation From Potential Suspicious Parent Location"
  description                = "Detects the execution of \"schtasks.exe\" from a parent that is located in a potentially suspicious location. Multiple malware strains were seen exhibiting a similar behavior in order to achieve persistence. - Software installers that run from temporary folders and also install scheduled tasks"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/Create " and FolderPath endswith "\\schtasks.exe" and (InitiatingProcessFolderPath contains ":\\Temp\\" or InitiatingProcessFolderPath contains "\\AppData\\Local\\" or InitiatingProcessFolderPath contains "\\AppData\\Roaming\\" or InitiatingProcessFolderPath contains "\\Temporary Internet" or InitiatingProcessFolderPath contains "\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\Windows\\Temp\\")) and (not((ProcessCommandLine contains "update_task.xml" or ProcessCommandLine contains "unattended.ini")))
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