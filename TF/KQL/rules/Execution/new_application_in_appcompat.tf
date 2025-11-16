resource "azurerm_sentinel_alert_rule_scheduled" "new_application_in_appcompat" {
  name                       = "new_application_in_appcompat"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Application in AppCompat"
  description                = "A General detection for a new application in AppCompat. This indicates an application executing for the first time on an endpoint. - Newly setup system. - Legitimate installation of new application."
  severity                   = "Informational"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\AppCompatFlags\\Compatibility Assistant\\Store*"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}