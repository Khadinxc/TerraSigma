resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_schtasks_schedule_types" {
  name                       = "suspicious_schtasks_schedule_types"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Schtasks Schedule Types"
  description                = "Detects scheduled task creations or modification on a suspicious schedule type - Legitimate processes that run at logon. Filter according to your environment"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe") and (ProcessCommandLine contains " ONLOGON " or ProcessCommandLine contains " ONSTART " or ProcessCommandLine contains " ONCE " or ProcessCommandLine contains " ONIDLE ")) and (not((ProcessCommandLine contains "NT AUT" or ProcessCommandLine contains " SYSTEM" or ProcessCommandLine contains "HIGHEST")))
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