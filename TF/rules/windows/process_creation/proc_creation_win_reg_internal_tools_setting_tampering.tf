resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_reg_internal_tools_setting_tampering" {
  name                       = "proc_creation_win_reg_internal_tools_setting_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Tampering Of Internal Tools Settings"
  description                = <<DESC
    Detects registry modifications that tamper with internal Windows tools settings, commonly used by malware to disable security features or system tools

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_internal_tools_setting_tampering.yml

    False Positives:
    - Legitimate use of reg.exe to change system settings
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "ConsentPromptBehaviorAdmin" or ProcessCommandLine contains "DisableChangePassword" or ProcessCommandLine contains "DisableCMD" or ProcessCommandLine contains "DisableLockWorkstation" or ProcessCommandLine contains "DisableNotificationCenter" or ProcessCommandLine contains "DisableRegistryTools" or ProcessCommandLine contains "DisableTaskmgr" or ProcessCommandLine contains "HideSCAHealth" or ProcessCommandLine contains "HideSCANetwork" or ProcessCommandLine contains "HideSCAVolume" or ProcessCommandLine contains "InactivityTimeoutSecs" or ProcessCommandLine contains "NoClose" or ProcessCommandLine contains "NoControlPanel" or ProcessCommandLine contains "NoDesktop" or ProcessCommandLine contains "NoDispBackgroundPage" or ProcessCommandLine contains "NoDispCPL" or ProcessCommandLine contains "NoDrives" or ProcessCommandLine contains "NoFileMenu" or ProcessCommandLine contains "NoFind" or ProcessCommandLine contains "NoLogOff" or ProcessCommandLine contains "NoPropertiesMyDocuments" or ProcessCommandLine contains "NoRun" or ProcessCommandLine contains "NoSetTaskbar" or ProcessCommandLine contains "NoTrayContextMenu" or ProcessCommandLine contains "StartMenuLogOff" or ProcessCommandLine contains "shutdownwithoutlogon") and (ProcessCommandLine contains "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" or ProcessCommandLine contains "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" or ProcessCommandLine contains "SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer" or ProcessCommandLine contains "SOFTWARE\\Policies\\Microsoft\\Windows\\System") and ProcessCommandLine contains " add " and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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