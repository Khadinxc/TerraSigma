resource "azurerm_sentinel_alert_rule_scheduled" "ntdllpipe_like_activity_execution" {
  name                       = "ntdllpipe_like_activity_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "NtdllPipe Like Activity Execution"
  description                = "Detects command that type the content of ntdll.dll to a different file or a pipe in order to evade AV / EDR detection. As seen being used in the POC NtdllPipe"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "type %windir%\\system32\\ntdll.dll" or ProcessCommandLine contains "type %systemroot%\\system32\\ntdll.dll" or ProcessCommandLine contains "type c:\\windows\\system32\\ntdll.dll" or ProcessCommandLine contains "\\ntdll.dll > \\\\.\\pipe\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
  }
}