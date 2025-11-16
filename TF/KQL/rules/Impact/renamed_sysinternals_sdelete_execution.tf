resource "azurerm_sentinel_alert_rule_scheduled" "renamed_sysinternals_sdelete_execution" {
  name                       = "renamed_sysinternals_sdelete_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed Sysinternals Sdelete Execution"
  description                = "Detects the use of a renamed SysInternals Sdelete, which is something an administrator shouldn't do (the renaming) - System administrator usage"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName =~ "sdelete.exe" and (not((FolderPath endswith "\\sdelete.exe" or FolderPath endswith "\\sdelete64.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1485"]
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