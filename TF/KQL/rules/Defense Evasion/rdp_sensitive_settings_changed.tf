resource "azurerm_sentinel_alert_rule_scheduled" "rdp_sensitive_settings_changed" {
  name                       = "rdp_sensitive_settings_changed"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "RDP Sensitive Settings Changed"
  description                = "Detects tampering of RDP Terminal Service/Server sensitive settings. Such as allowing unauthorized users access to a system via the 'fAllowUnsolicited' or enabling RDP via 'fDenyTSConnections'...etc - Some of the keys mentioned here could be modified by an administrator while setting group policy (it should be investigated either way)"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData in~ ("DWORD (0x00000001)", "DWORD (0x00000002)", "DWORD (0x00000003)", "DWORD (0x00000004)")) and (RegistryKey endswith "\\Control\\Terminal Server*" or RegistryKey endswith "\\Windows NT\\Terminal Services*") and RegistryKey endswith "\\Shadow") or (RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey endswith "\\Control\\Terminal Server*" or RegistryKey endswith "\\Windows NT\\Terminal Services*") and (RegistryKey endswith "\\DisableRemoteDesktopAntiAlias" or RegistryKey endswith "\\DisableSecuritySettings" or RegistryKey endswith "\\fAllowUnsolicited" or RegistryKey endswith "\\fAllowUnsolicitedFullControl")) or (RegistryKey contains "\\Control\\Terminal Server\\InitialProgram" or RegistryKey contains "\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram" or RegistryKey contains "\\services\\TermService\\Parameters\\ServiceDll" or RegistryKey contains "\\Windows NT\\Terminal Services\\InitialProgram")
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