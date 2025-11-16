resource "azurerm_sentinel_alert_rule_scheduled" "rdp_sensitive_settings_changed_to_zero" {
  name                       = "rdp_sensitive_settings_changed_to_zero"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "RDP Sensitive Settings Changed to Zero"
  description                = "Detects tampering of RDP Terminal Service/Server sensitive settings. Such as allowing unauthorized users access to a system via the 'fAllowUnsolicited' or enabling RDP via 'fDenyTSConnections', etc. - Some of the keys mentioned here could be modified by an administrator while setting group policy (it should be investigated either way)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey endswith "\\fDenyTSConnections" or RegistryKey endswith "\\fSingleSessionPerUser" or RegistryKey endswith "\\UserAuthentication")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
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