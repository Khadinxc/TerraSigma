resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_outlook_macro_created" {
  name                       = "suspicious_outlook_macro_created"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Outlook Macro Created"
  description                = "Detects the creation of a macro file for Outlook. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\Microsoft\\Outlook\\VbaProject.OTM" and (not(InitiatingProcessFolderPath endswith "\\outlook.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "CommandAndControl"]
  techniques                 = ["T1137", "T1008", "T1546"]
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