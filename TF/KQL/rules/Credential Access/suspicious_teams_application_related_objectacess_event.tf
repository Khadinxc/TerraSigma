resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_teams_application_related_objectacess_event" {
  name                       = "suspicious_teams_application_related_objectacess_event"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Teams Application Related ObjectAcess Event"
  description                = "Detects an access to authentication tokens and accounts of Microsoft Teams desktop application."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\Microsoft\\Teams\\Cookies" or RegistryKey contains "\\Microsoft\\Teams\\Local Storage\\leveldb") and (not(InitiatingProcessFolderPath contains "\\Microsoft\\Teams\\current\\Teams.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1528"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}