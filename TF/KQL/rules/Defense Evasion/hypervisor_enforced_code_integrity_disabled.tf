resource "azurerm_sentinel_alert_rule_scheduled" "hypervisor_enforced_code_integrity_disabled" {
  name                       = "hypervisor_enforced_code_integrity_disabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Hypervisor Enforced Code Integrity Disabled"
  description                = "Detects changes to the HypervisorEnforcedCodeIntegrity registry key and the \"Enabled\" value being set to 0 in order to disable the Hypervisor Enforced Code Integrity feature. This allows an attacker to load unsigned and untrusted code to be run in the kernel"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey endswith "\\Microsoft\\Windows\\DeviceGuard\\HypervisorEnforcedCodeIntegrity" or RegistryKey endswith "\\Control\\DeviceGuard\\HypervisorEnforcedCodeIntegrity" or RegistryKey endswith "\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled")
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