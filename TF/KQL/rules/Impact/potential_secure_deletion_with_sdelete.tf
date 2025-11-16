resource "azurerm_sentinel_alert_rule_scheduled" "potential_secure_deletion_with_sdelete" {
  name                       = "potential_secure_deletion_with_sdelete"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Secure Deletion with SDelete"
  description                = "Detects files that have extensions commonly seen while SDelete is used to wipe files. - Legitimate usage of SDelete - Files that are interacted with that have these extensions legitimately"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith ".AAA" or RegistryKey endswith ".ZZZ"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact", "DefenseEvasion"]
  techniques                 = ["T1070", "T1027", "T1485", "T1553"]
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