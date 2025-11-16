resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_drop_by_exchange" {
  name                       = "suspicious_file_drop_by_exchange"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Drop by Exchange"
  description                = "Detects suspicious file type dropped by an Exchange component in IIS"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessCommandLine contains "MSExchange" and InitiatingProcessFolderPath endswith "\\w3wp.exe") and (FolderPath endswith ".aspx" or FolderPath endswith ".asp" or FolderPath endswith ".ashx" or FolderPath endswith ".ps1" or FolderPath endswith ".bat" or FolderPath endswith ".exe" or FolderPath endswith ".dll" or FolderPath endswith ".vbs")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "InitialAccess"]
  techniques                 = ["T1190", "T1505"]
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
      column_name = "InitiatingProcessCommandLine"
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