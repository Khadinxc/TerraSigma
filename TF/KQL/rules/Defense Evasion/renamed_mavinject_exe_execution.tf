resource "azurerm_sentinel_alert_rule_scheduled" "renamed_mavinject_exe_execution" {
  name                       = "renamed_mavinject_exe_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed Mavinject.EXE Execution"
  description                = "Detects the execution of a renamed version of the \"Mavinject\" process. Which can be abused to perform process injection using the \"/INJECTRUNNING\" flag - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoOriginalFileName in~ ("mavinject32.exe", "mavinject64.exe")) and (not((FolderPath endswith "\\mavinject32.exe" or FolderPath endswith "\\mavinject64.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1055", "T1218"]
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