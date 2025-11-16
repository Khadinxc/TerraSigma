resource "azurerm_sentinel_alert_rule_scheduled" "unc4841_email_exfiltration_file_pattern" {
  name                       = "unc4841_email_exfiltration_file_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UNC4841 - Email Exfiltration File Pattern"
  description                = "Detects filename pattern of email related data used by UNC4841 for staging and exfiltration"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath matches regex "/mail/tmp/[a-zA-Z0-9]{3}[0-9]{3}\\.tar\\.gz"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence", "DefenseEvasion"]
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