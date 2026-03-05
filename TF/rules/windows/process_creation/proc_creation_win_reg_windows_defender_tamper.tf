resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_reg_windows_defender_tamper" {
  name                       = "proc_creation_win_reg_windows_defender_tamper"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Windows Defender Registry Key Tampering Via Reg.EXE"
  description                = <<DESC
    Detects the usage of "reg.exe" to tamper with different Windows Defender registry keys in order to disable some important features related to protection and detection

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_windows_defender_tamper.yml

    False Positives:
    - Rare legitimate use by administrators to test software (should always be investigated)
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe") and (ProcessCommandLine contains "SOFTWARE\\Microsoft\\Windows Defender\\" or ProcessCommandLine contains "SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center" or ProcessCommandLine contains "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\")) and (((ProcessCommandLine contains "DisallowExploitProtectionOverride" or ProcessCommandLine contains "EnableControlledFolderAccess" or ProcessCommandLine contains "MpEnablePus" or ProcessCommandLine contains "PUAProtection" or ProcessCommandLine contains "SpynetReporting" or ProcessCommandLine contains "SubmitSamplesConsent" or ProcessCommandLine contains "TamperProtection") and (ProcessCommandLine contains " add " and ProcessCommandLine contains "d 0")) or ((ProcessCommandLine contains "DisableAccess" or ProcessCommandLine contains "DisableAntiSpyware" or ProcessCommandLine contains "DisableAntiSpywareRealtimeProtection" or ProcessCommandLine contains "DisableAntiVirus" or ProcessCommandLine contains "DisableAntiVirusSignatures" or ProcessCommandLine contains "DisableArchiveScanning" or ProcessCommandLine contains "DisableBehaviorMonitoring" or ProcessCommandLine contains "DisableBlockAtFirstSeen" or ProcessCommandLine contains "DisableCloudProtection" or ProcessCommandLine contains "DisableConfig" or ProcessCommandLine contains "DisableEnhancedNotifications" or ProcessCommandLine contains "DisableIntrusionPreventionSystem" or ProcessCommandLine contains "DisableIOAVProtection" or ProcessCommandLine contains "DisableNetworkProtection" or ProcessCommandLine contains "DisableOnAccessProtection" or ProcessCommandLine contains "DisablePrivacyMode" or ProcessCommandLine contains "DisableRealtimeMonitoring" or ProcessCommandLine contains "DisableRoutinelyTakingAction" or ProcessCommandLine contains "DisableScanOnRealtimeEnable" or ProcessCommandLine contains "DisableScriptScanning" or ProcessCommandLine contains "DisableSecurityCenter" or ProcessCommandLine contains "Notification_Suppress" or ProcessCommandLine contains "SignatureDisableUpdateOnStartupWithoutEngine") and (ProcessCommandLine contains " add " and ProcessCommandLine contains "d 1")))
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}