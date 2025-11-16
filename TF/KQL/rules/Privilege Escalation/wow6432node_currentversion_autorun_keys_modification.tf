resource "azurerm_sentinel_alert_rule_scheduled" "wow6432node_currentversion_autorun_keys_modification" {
  name                       = "wow6432node_currentversion_autorun_keys_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wow6432Node CurrentVersion Autorun Keys Modification"
  description                = "Detects modification of autostart extensibility point (ASEP) in registry. - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason - Legitimate administrator sets up autorun keys for legitimate reason"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion" and (RegistryKey contains "\\ShellServiceObjectDelayLoad" or RegistryKey endswith "\\Run*" or RegistryKey endswith "\\RunOnce*" or RegistryKey endswith "\\RunOnceEx*" or RegistryKey endswith "\\RunServices*" or RegistryKey endswith "\\RunServicesOnce*" or RegistryKey contains "\\Explorer\\ShellServiceObjects" or RegistryKey contains "\\Explorer\\ShellIconOverlayIdentifiers" or RegistryKey contains "\\Explorer\\ShellExecuteHooks" or RegistryKey contains "\\Explorer\\SharedTaskScheduler" or RegistryKey contains "\\Explorer\\Browser Helper Objects")) and (not(((InitiatingProcessFolderPath contains "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\Install\\{" and InitiatingProcessFolderPath contains "\\setup.exe") or RegistryValueData =~ "(Empty)" or RegistryValueData startswith "\"C:\\ProgramData\\Package Cache\\{d21a4f20-968a-4b0c-bf04-a38da5f06e41}\\windowsdesktop-runtime-" or (InitiatingProcessFolderPath =~ "C:\\WINDOWS\\system32\\msiexec.exe" and RegistryKey endswith "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*") or (InitiatingProcessFolderPath startswith "C:\\Windows\\Installer\\MSI" and RegistryKey contains "\\Explorer\\Browser Helper Objects") or (RegistryValueData endswith " /burn.runonce" and (InitiatingProcessFolderPath contains "\\winsdksetup.exe" or InitiatingProcessFolderPath contains "\\windowsdesktop-runtime-" or InitiatingProcessFolderPath contains "\\AspNetCoreSharedFrameworkBundle-") and (InitiatingProcessFolderPath startswith "C:\\ProgramData\\Package Cache" or InitiatingProcessFolderPath startswith "C:\\Windows\\Temp\\")) or (RegistryValueData endswith "}\\VC_redist.x64.exe\" /burn.runonce" and InitiatingProcessFolderPath endswith "\\VC_redist.x64.exe")))) and (not(((RegistryValueData endswith "instup.exe\" /instop:repair /wait" and InitiatingProcessFolderPath endswith "\\instup.exe" and RegistryKey endswith "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\AvRepair") or ((RegistryValueData in~ ("{472083B1-C522-11CF-8763-00608CC02F24}", "{472083B0-C522-11CF-8763-00608CC02F24}")) and InitiatingProcessFolderPath endswith "\\instup.exe" and (RegistryKey endswith "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00avg\\(Default)" or RegistryKey endswith "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00asw\\(Default)")) or (RegistryValueData endswith "\\Avira.OE.Setup.Bundle.exe\" /burn.runonce" and InitiatingProcessFolderPath endswith "\\Avira.OE.Setup.Bundle.exe") or (RegistryValueData endswith "Discord.exe --checkInstall" and RegistryKey endswith "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\Discord") or (RegistryValueData endswith ".exe\" /burn.runonce" and RegistryValueData startswith "\"C:\\ProgramData\\Package Cache\\" and InitiatingProcessFolderPath contains "\\windowsdesktop-runtime-" and (RegistryKey endswith "\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\{e2d1ae32-dd1d-4ad7-a298-10e42e7840fc}" or RegistryKey endswith "\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\{7037b699-7382-448c-89a7-4765961d2537}")) or (RegistryValueData endswith "-A251-47B7-93E1-CDD82E34AF8B}" or RegistryValueData =~ "grpconv -o" or (RegistryValueData contains "C:\\Program Files" and RegistryValueData contains "\\Dropbox\\Client\\Dropbox.exe" and RegistryValueData contains " /systemstartup")) or RegistryKey endswith "\\Explorer\\Browser Helper Objects\\{92EF2EAD-A7CE-4424-B0DB-499CF856608E}\\NoExplorer" or (InitiatingProcessFolderPath =~ "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe" and RegistryKey endswith "\\Office\\ClickToRun\\REGISTRY\\MACHINE\\Software\\Wow6432Node*") or ((InitiatingProcessFolderPath in~ ("C:\\Program Files\\Microsoft Office\\root\\integration\\integrator.exe", "C:\\Program Files (x86)\\Microsoft Office\\root\\integration\\integrator.exe")) and RegistryKey endswith "\\Explorer\\Browser Helper Objects\\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}*") or (InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\Updates\\")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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