resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_dropbox_api_usage" {
  name                       = "suspicious_dropbox_api_usage"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Dropbox API Usage"
  description                = "Detects an executable that isn't dropbox but communicates with the Dropbox API - Legitimate use of the API with a tool that the author wasn't aware of"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemoteUrl endswith "api.dropboxapi.com" or RemoteUrl endswith "content.dropboxapi.com") and (not(InitiatingProcessFolderPath contains "\\Dropbox"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "Exfiltration"]
  techniques                 = ["T1105", "T1567"]
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
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "URL"
    field_mapping {
      identifier  = "Url"
      column_name = "RemoteUrl"
    }
  }
}