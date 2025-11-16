resource "azurerm_sentinel_alert_rule_scheduled" "disable_windows_defender_functionalities_via_registry_keys" {
  name                       = "disable_windows_defender_functionalities_via_registry_keys"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Windows Defender Functionalities Via Registry Keys"
  description                = "Detects when attackers or tools disable Windows Defender functionalities via the Windows registry - Administrator actions via the Windows Defender interface - Third party Antivirus"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows Defender*" or RegistryKey endswith "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center*" or RegistryKey endswith "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender*") and ((RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey endswith "\\DisallowExploitProtectionOverride" or RegistryKey endswith "\\Features\\TamperProtection" or RegistryKey endswith "\\MpEngine\\MpEnablePus" or RegistryKey endswith "\\PUAProtection" or RegistryKey endswith "\\Signature Update\\ForceUpdateFromMU" or RegistryKey endswith "\\SpyNet\\SpynetReporting" or RegistryKey endswith "\\SpyNet\\SubmitSamplesConsent" or RegistryKey endswith "\\Windows Defender Exploit Guard\\Controlled Folder Access\\EnableControlledFolderAccess")) or (RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey endswith "\\DisableAntiSpyware" or RegistryKey endswith "\\DisableAntiVirus" or RegistryKey endswith "\\DisableBehaviorMonitoring" or RegistryKey endswith "\\DisableBlockAtFirstSeen" or RegistryKey endswith "\\DisableEnhancedNotifications" or RegistryKey endswith "\\DisableIntrusionPreventionSystem" or RegistryKey endswith "\\DisableIOAVProtection" or RegistryKey endswith "\\DisableOnAccessProtection" or RegistryKey endswith "\\DisableRealtimeMonitoring" or RegistryKey endswith "\\DisableScanOnRealtimeEnable" or RegistryKey endswith "\\DisableScriptScanning"))) and (not((InitiatingProcessFolderPath endswith "\\sepWscSvc64.exe" and InitiatingProcessFolderPath startswith "C:\\Program Files\\Symantec\\Symantec Endpoint Protection\\")))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
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