resource "azurerm_sentinel_alert_rule_scheduled" "wdigest_credguard_registry_modification" {
  name                       = "wdigest_credguard_registry_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wdigest CredGuard Registry Modification"
  description                = "Detects potential malicious modification of the property value of IsCredGuardEnabled from HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest to disable Cred Guard on a system. This is usually used with UseLogonCredential to manipulate the caching credentials."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\IsCredGuardEnabled"
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
  }
}