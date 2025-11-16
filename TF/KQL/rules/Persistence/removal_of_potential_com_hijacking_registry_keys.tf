resource "azurerm_sentinel_alert_rule_scheduled" "removal_of_potential_com_hijacking_registry_keys" {
  name                       = "removal_of_potential_com_hijacking_registry_keys"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Removal of Potential COM Hijacking Registry Keys"
  description                = "Detects any deletion of entries in \".*\\shell\\open\\command\" registry keys. These registry keys might have been used for COM hijacking activities by a threat actor or an attacker and the deletion could indicate steps to remove its tracks. - Legitimate software (un)installations are known to cause false positives. Please add them as a filter when encountered"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\shell\\open\\command" and (not((InitiatingProcessFolderPath endswith "C:\\Windows\\explorer.exe" or (InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\") or (InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")) or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\OpenWith.exe" or InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\svchost.exe"))) and (not((((InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Avira\\Antivirus\\", "C:\\Program Files\\Avira\\Antivirus\\")) and (RegistryKey endswith "\\CLSID\\{305CA226-D286-468e-B848-2B2E8E697B74}\\Shell\\Open\\Command" or RegistryKey endswith "\\AntiVir.Keyfile\\shell\\open\\command")) or (InitiatingProcessFolderPath endswith "\\reg.exe" and RegistryKey endswith "\\Discord\\shell\\open\\command") or (InitiatingProcessFolderPath endswith "\\Dropbox.exe" and RegistryKey contains "\\Dropbox.") or (InitiatingProcessFolderPath endswith "C:\\eclipse\\eclipse.exe" and RegistryKey contains "_Classes\\eclipse+") or InitiatingProcessFolderPath contains "\\Microsoft\\EdgeUpdate\\Install" or (InitiatingProcessFolderPath endswith "\\Everything.exe" and RegistryKey contains "\\Everything.") or ((InitiatingProcessFolderPath contains "AppData\\Local\\Temp" and InitiatingProcessFolderPath contains "\\setup.exe") or (InitiatingProcessFolderPath contains "\\Temp\\is-" and InitiatingProcessFolderPath contains "\\target.tmp")) or (InitiatingProcessFolderPath endswith "\\installer.exe" and InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Java\\" and RegistryKey contains "\\Classes\\WOW6432Node\\CLSID\\{4299124F-F2C3-41b4-9C73-9236B2AD0E8F}") or InitiatingProcessFolderPath endswith "\\ninite.exe" or (InitiatingProcessFolderPath contains "peazip" and RegistryKey contains "\\PeaZip.") or (InitiatingProcessFolderPath endswith "\\Spotify.exe" and RegistryKey endswith "\\Spotify\\shell\\open\\command") or (InitiatingProcessFolderPath contains "\\Temp" and InitiatingProcessFolderPath contains "\\TeamViewer") or InitiatingProcessFolderPath startswith "C:\\Windows\\Installer\\MSI" or (InitiatingProcessFolderPath endswith "\\AppData\\Local\\Temp\\Wireshark_uninstaller.exe" and RegistryKey endswith "\\wireshark-capture-file*"))))
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
  }
}