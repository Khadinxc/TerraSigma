resource "azurerm_sentinel_alert_rule_scheduled" "currentversion_nt_autorun_keys_modification" {
  name                       = "currentversion_nt_autorun_keys_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "CurrentVersion NT Autorun Keys Modification"
  description                = "Detects modification of autostart extensibility point (ASEP) in registry. - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason - Legitimate administrator sets up autorun keys for legitimate reason"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey contains "\\Winlogon\\VmApplet" or RegistryKey contains "\\Winlogon\\Userinit" or RegistryKey contains "\\Winlogon\\Taskman" or RegistryKey contains "\\Winlogon\\Shell" or RegistryKey contains "\\Winlogon\\GpExtensions" or RegistryKey contains "\\Winlogon\\AppSetup" or RegistryKey contains "\\Winlogon\\AlternateShells\\AvailableShells" or RegistryKey contains "\\Windows\\IconServiceLib" or RegistryKey contains "\\Windows\\Appinit_Dlls" or RegistryKey contains "\\Image File Execution Options" or RegistryKey contains "\\Font Drivers" or RegistryKey contains "\\Drivers32" or RegistryKey contains "\\Windows\\Run" or RegistryKey contains "\\Windows\\Load") and RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") and (not((RegistryValueData =~ "(Empty)" or (RegistryKey endswith "\\Image File Execution Options*" and (RegistryKey endswith "\\DisableExceptionChainValidation" or RegistryKey endswith "\\MitigationOptions")) or isnull(RegistryValueData) or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\poqexec.exe" or (InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\RuntimeBroker.exe" and RegistryKey contains "\\runtimebroker.exe\\Microsoft.Windows.ShellExperienceHost") or ((RegistryValueData in~ ("DWORD (0x00000001)", "DWORD (0x00000009)", "DWORD (0x000003c0)")) and InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\svchost.exe" and (RegistryKey contains "\\Winlogon\\GPExtensions\\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\\PreviousPolicyAreas" or RegistryKey contains "\\Winlogon\\GPExtensions\\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\\MaxNoGPOListChangesInterval"))))) and (not((((RegistryValueData in~ ("explorer.exe", "C:\\Windows\\system32\\userinit.exe,")) and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Avira\\Antivirus\\avguard.exe" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Avira\\Antivirus\\avguard.exe") and RegistryKey endswith "SOFTWARE\\WOW6432Node\\Avira\\Antivirus\\Overwrite_Keys\\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*" and (RegistryKey endswith "\\userinit\\UseAsDefault" or RegistryKey endswith "\\shell\\UseAsDefault")) or (InitiatingProcessFolderPath endswith "\\MicrosoftEdgeUpdate.exe" and InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\Temp\\") or ((RegistryKey endswith "\\ClickToRunStore\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion*" or RegistryKey endswith "\\ClickToRun\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion*") or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Microsoft Office\\root\\integration\\integrator.exe", "C:\\Program Files (x86)\\Microsoft Office\\root\\integration\\integrator.exe"))) or (InitiatingProcessFolderPath endswith "\\ngen.exe" and InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework") or (InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\Updates\\")) or (RegistryValueData endswith "\\AppData\\Local\\Microsoft\\OneDrive\\Update\\OneDriveSetup.exe\"" and RegistryValueData startswith "C:\\Windows\\system32\\cmd.exe /q /c del /q \"C:\\Users\\" and InitiatingProcessFolderPath endswith "\\AppData\\Local\\Microsoft\\OneDrive\\StandaloneUpdater\\OneDriveSetup.exe" and RegistryKey endswith "\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Delete Cached Update Binary"))))
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