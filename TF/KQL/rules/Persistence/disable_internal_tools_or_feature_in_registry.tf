resource "azurerm_sentinel_alert_rule_scheduled" "disable_internal_tools_or_feature_in_registry" {
  name                       = "disable_internal_tools_or_feature_in_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Internal Tools or Feature in Registry"
  description                = "Detects registry modifications that change features of internal Windows tools (malware like Agent Tesla uses this technique) - Legitimate admin script"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin" or RegistryKey endswith "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\shutdownwithoutlogon" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\ToastEnabled" or RegistryKey endswith "SYSTEM\\CurrentControlSet\\Control\\Storage\\Write Protection" or RegistryKey endswith "SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\\WriteProtect")) or (RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisableCMD" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoControlPanel" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\StartMenuLogOff" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableChangePassword" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableLockWorkstation" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskmgr" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\NoDispBackgroundPage" or RegistryKey endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\NoDispCPL" or RegistryKey endswith "SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\DisableNotificationCenter" or RegistryKey endswith "SOFTWARE\\Policies\\Microsoft\\Windows\\System\\DisableCMD"))
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