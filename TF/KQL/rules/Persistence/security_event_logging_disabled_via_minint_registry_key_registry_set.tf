resource "azurerm_sentinel_alert_rule_scheduled" "security_event_logging_disabled_via_minint_registry_key_registry_set" {
  name                       = "security_event_logging_disabled_via_minint_registry_key_registry_set"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Security Event Logging Disabled via MiniNt Registry Key - Registry Set"
  description                = "Detects the addition of the 'MiniNt' key to the registry. Upon a reboot, Windows Event Log service will stop writing events. Windows Event Log is a service that collects and stores event logs from the operating system and applications. It is an important component of Windows security and auditing. Adversary may want to disable this service to disable logging of security events which could be used to detect their activities. - Highly Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey =~ "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001\\Control\\MiniNt\\(Default)"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1562", "T1112"]
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