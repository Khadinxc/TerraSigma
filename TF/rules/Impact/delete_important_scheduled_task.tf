resource "azurerm_sentinel_alert_rule_scheduled" "delete_important_scheduled_task" {
  name                       = "delete_important_scheduled_task"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Delete Important Scheduled Task"
  description                = "Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\Windows\\BitLocker" or ProcessCommandLine contains "\\Windows\\ExploitGuard" or ProcessCommandLine contains "\\Windows\\SystemRestore\\SR" or ProcessCommandLine contains "\\Windows\\UpdateOrchestrator\\" or ProcessCommandLine contains "\\Windows\\Windows Defender\\" or ProcessCommandLine contains "\\Windows\\WindowsBackup\\" or ProcessCommandLine contains "\\Windows\\WindowsUpdate\\") and (ProcessCommandLine contains "/delete" and ProcessCommandLine contains "/tn") and FolderPath endswith "\\schtasks.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1489"]
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