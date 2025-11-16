resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_schtasks_schedule_type_with_high_privileges" {
  name                       = "suspicious_schtasks_schedule_type_with_high_privileges"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Schtasks Schedule Type With High Privileges"
  description                = "Detects scheduled task creations or modification to be run with high privileges on a suspicious schedule type - Some installers were seen using this method of creation unfortunately. Filter them in your environment"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe") and (ProcessCommandLine contains "NT AUT" or ProcessCommandLine contains " SYSTEM" or ProcessCommandLine contains "HIGHEST") and (ProcessCommandLine contains " ONLOGON " or ProcessCommandLine contains " ONSTART " or ProcessCommandLine contains " ONCE " or ProcessCommandLine contains " ONIDLE ")
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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