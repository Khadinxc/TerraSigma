resource "azurerm_sentinel_alert_rule_scheduled" "apt29_2018_phishing_campaign_file_indicators" {
  name                       = "apt29_2018_phishing_campaign_file_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "APT29 2018 Phishing Campaign File Indicators"
  description                = "Detects indicators of APT 29 (Cozy Bear) phishing-campaign as reported by mandiant - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "ds7002.lnk" or FolderPath contains "ds7002.pdf" or FolderPath contains "ds7002.zip"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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