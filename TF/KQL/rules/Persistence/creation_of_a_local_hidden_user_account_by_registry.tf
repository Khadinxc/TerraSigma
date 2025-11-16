resource "azurerm_sentinel_alert_rule_scheduled" "creation_of_a_local_hidden_user_account_by_registry" {
  name                       = "creation_of_a_local_hidden_user_account_by_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Creation of a Local Hidden User Account by Registry"
  description                = "Sysmon registry detection of a local hidden user account."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where InitiatingProcessFolderPath endswith "\\lsass.exe" and RegistryKey endswith "\\SAM\\SAM\\Domains\\Account\\Users\\Names*" and RegistryKey endswith "$"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1136"]
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