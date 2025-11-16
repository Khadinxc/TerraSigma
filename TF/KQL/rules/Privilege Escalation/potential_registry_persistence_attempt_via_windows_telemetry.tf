resource "azurerm_sentinel_alert_rule_scheduled" "potential_registry_persistence_attempt_via_windows_telemetry" {
  name                       = "potential_registry_persistence_attempt_via_windows_telemetry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Registry Persistence Attempt Via Windows Telemetry"
  description                = "Detects potential persistence behavior using the windows telemetry registry key. Windows telemetry makes use of the binary CompatTelRunner.exe to run a variety of commands and perform the actual telemetry collections. This binary was created to be easily extensible, and to that end, it relies on the registry to instruct on which commands to run. The problem is, it will run any arbitrary command without restriction of location or type."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData contains ".bat" or RegistryValueData contains ".bin" or RegistryValueData contains ".cmd" or RegistryValueData contains ".dat" or RegistryValueData contains ".dll" or RegistryValueData contains ".exe" or RegistryValueData contains ".hta" or RegistryValueData contains ".jar" or RegistryValueData contains ".js" or RegistryValueData contains ".msi" or RegistryValueData contains ".ps" or RegistryValueData contains ".sh" or RegistryValueData contains ".vb") and RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController*" and RegistryKey endswith "\\Command") and (not((RegistryValueData contains "\\system32\\CompatTelRunner.exe" or RegistryValueData contains "\\system32\\DeviceCensus.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053"]
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