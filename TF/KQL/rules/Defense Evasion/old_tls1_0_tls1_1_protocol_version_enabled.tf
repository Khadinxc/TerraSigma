resource "azurerm_sentinel_alert_rule_scheduled" "old_tls1_0_tls1_1_protocol_version_enabled" {
  name                       = "old_tls1_0_tls1_1_protocol_version_enabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Old TLS1.0/TLS1.1 Protocol Version Enabled"
  description                = "Detects applications or users re-enabling old TLS versions by setting the \"Enabled\" value to \"1\" for the \"Protocols\" registry key. - Legitimate enabling of the old tls versions due to incompatibility"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey endswith "\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0*" or RegistryKey endswith "\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1*") and RegistryKey endswith "\\Enabled"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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