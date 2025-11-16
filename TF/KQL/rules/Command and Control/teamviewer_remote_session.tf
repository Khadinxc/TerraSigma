resource "azurerm_sentinel_alert_rule_scheduled" "teamviewer_remote_session" {
  name                       = "teamviewer_remote_session"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "TeamViewer Remote Session"
  description                = "Detects the creation of log files during a TeamViewer remote session - Legitimate uses of TeamViewer in an organisation"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "\\TeamViewer\\RemotePrinting\\tvprint.db" or FolderPath endswith "\\TeamViewer\\TVNetwork.log") or (FolderPath contains "\\TeamViewer" and FolderPath contains "_Logfile.log")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]
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