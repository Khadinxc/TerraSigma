resource "azurerm_sentinel_alert_rule_scheduled" "hybridconnectionmanager_service_installation_registry" {
  name                       = "hybridconnectionmanager_service_installation_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HybridConnectionManager Service Installation - Registry"
  description                = "Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Services\\HybridConnectionManager" or (RegistryValueData contains "Microsoft.HybridConnectionManager.Listener.exe" and ActionType =~ "RegistryValueSet")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1608"]
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}