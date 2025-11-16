resource "azurerm_sentinel_alert_rule_scheduled" "tamper_with_sophos_av_registry_keys" {
  name                       = "tamper_with_sophos_av_registry_keys"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Tamper With Sophos AV Registry Keys"
  description                = "Detects tamper attempts to sophos av functionality via registry key modification - Some FP may occur when the feature is disabled by the AV itself, you should always investigate if the action was legitimate"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey contains "\\Sophos Endpoint Defense\\TamperProtection\\Config\\SAVEnabled" or RegistryKey contains "\\Sophos Endpoint Defense\\TamperProtection\\Config\\SEDEnabled" or RegistryKey contains "\\Sophos\\SAVService\\TamperProtection\\Enabled")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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