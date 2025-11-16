resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_default_powersploit_empire_scheduled_task_creation" {
  name                       = "hacktool_default_powersploit_empire_scheduled_task_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Default PowerSploit/Empire Scheduled Task Creation"
  description                = "Detects the creation of a schtask via PowerSploit or Empire Default Configuration. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/SC ONLOGON" or ProcessCommandLine contains "/SC DAILY /ST" or ProcessCommandLine contains "/SC ONIDLE" or ProcessCommandLine contains "/SC HOURLY") and (ProcessCommandLine contains "/Create" and ProcessCommandLine contains "powershell.exe -NonI" and ProcessCommandLine contains "/TN Updater /TR") and FolderPath endswith "\\schtasks.exe" and (InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1053", "T1059"]
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