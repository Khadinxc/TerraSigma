resource "azurerm_sentinel_alert_rule_scheduled" "enable_lm_hash_storage" {
  name                       = "enable_lm_hash_storage"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Enable LM Hash Storage"
  description                = "Detects changes to the \"NoLMHash\" registry value in order to allow Windows to store LM Hashes. By setting this registry value to \"0\" (DWORD), Windows will be allowed to store a LAN manager hash of your password in Active Directory and local SAM databases."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey endswith "System\\CurrentControlSet\\Control\\Lsa\\NoLMHash"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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