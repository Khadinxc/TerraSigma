resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_outlook_form" {
  name                       = "potential_persistence_via_outlook_form"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Outlook Form"
  description                = "Detects the creation of a new Outlook form which can contain malicious code - Legitimate use of outlook forms"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\outlook.exe" and (FolderPath contains "\\AppData\\Local\\Microsoft\\FORMS\\IPM" or FolderPath contains "\\Local Settings\\Application Data\\Microsoft\\Forms")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1137"]
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