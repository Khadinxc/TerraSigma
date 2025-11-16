resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_mimikatz_kirbi_file_creation" {
  name                       = "hacktool_mimikatz_kirbi_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Mimikatz Kirbi File Creation"
  description                = "Detects the creation of files created by mimikatz such as \".kirbi\", \"mimilsa.log\", etc. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".kirbi" or FolderPath endswith "mimilsa.log"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1558"]
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