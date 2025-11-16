resource "azurerm_sentinel_alert_rule_scheduled" "psexec_service_file_creation" {
  name                       = "psexec_service_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PsExec Service File Creation"
  description                = "Detects default PsExec service filename which indicates PsExec service installation and execution"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\PSEXESVC.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1569"]
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