resource "azurerm_sentinel_alert_rule_scheduled" "netntlm_downgrade_attack_registry" {
  name                       = "netntlm_downgrade_attack_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "NetNTLM Downgrade Attack - Registry"
  description                = "Detects NetNTLM downgrade attack - Services or tools that set the values to more restrictive values"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "SYSTEM*" and RegistryKey contains "ControlSet" and RegistryKey contains "\\Control\\Lsa") and (((RegistryValueData in~ ("DWORD (0x00000000)", "DWORD (0x00000001)", "DWORD (0x00000002)")) and RegistryKey endswith "\\lmcompatibilitylevel") or ((RegistryValueData in~ ("DWORD (0x00000000)", "DWORD (0x00000010)", "DWORD (0x00000020)", "DWORD (0x00000030)")) and RegistryKey endswith "\\NtlmMinClientSec") or RegistryKey endswith "\\RestrictSendingNTLMTraffic")
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}