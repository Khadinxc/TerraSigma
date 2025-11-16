resource "azurerm_sentinel_alert_rule_scheduled" "moriya_rootkit_file_created" {
  name                       = "moriya_rootkit_file_created"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Moriya Rootkit File Created"
  description                = "Detects the creation of a file named \"MoriyaStreamWatchmen.sys\" in a specific location. This filename was reported to be related to the Moriya rootkit as described in the securelist's Operation TunnelSnake report."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath =~ "C:\\Windows\\System32\\drivers\\MoriyaStreamWatchmen.sys"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1543"]
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