resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_execution_of_installutil_without_log" {
  name                       = "suspicious_execution_of_installutil_without_log"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Execution of InstallUtil Without Log"
  description                = "Uses the .NET InstallUtil.exe application in order to execute image without log"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/logfile= " and ProcessCommandLine contains "/LogToConsole=false") and FolderPath contains "Microsoft.NET\\Framework" and FolderPath endswith "\\InstallUtil.exe"
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