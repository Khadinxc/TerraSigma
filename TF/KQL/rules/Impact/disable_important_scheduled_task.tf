resource "azurerm_sentinel_alert_rule_scheduled" "disable_important_scheduled_task" {
  name                       = "disable_important_scheduled_task"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Important Scheduled Task"
  description                = "Detects when adversaries stop services or processes by disabling their respective scheduled tasks in order to conduct data destructive activities"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\Windows\\BitLocker" or ProcessCommandLine contains "\\Windows\\ExploitGuard" or ProcessCommandLine contains "\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh" or ProcessCommandLine contains "\\Windows\\SystemRestore\\SR" or ProcessCommandLine contains "\\Windows\\UpdateOrchestrator\\" or ProcessCommandLine contains "\\Windows\\Windows Defender\\" or ProcessCommandLine contains "\\Windows\\WindowsBackup\\" or ProcessCommandLine contains "\\Windows\\WindowsUpdate\\") and (ProcessCommandLine contains "/Change" and ProcessCommandLine contains "/TN" and ProcessCommandLine contains "/disable") and FolderPath endswith "\\schtasks.exe"
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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