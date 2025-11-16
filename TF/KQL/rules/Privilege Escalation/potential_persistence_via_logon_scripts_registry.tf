resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_logon_scripts_registry" {
  name                       = "potential_persistence_via_logon_scripts_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Logon Scripts - Registry"
  description                = "Detects creation of \"UserInitMprLogonScript\" registry value which can be used as a persistence method by malicious actors - Investigate the contents of the \"UserInitMprLogonScript\" value to determine of the added script is legitimate"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ActionType =~ "RegistryKeyCreated" and RegistryKey contains "UserInitMprLogonScript"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "LateralMovement"]
  techniques                 = ["T1037"]
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