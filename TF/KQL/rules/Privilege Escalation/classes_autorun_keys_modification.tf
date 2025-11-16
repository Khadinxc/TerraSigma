resource "azurerm_sentinel_alert_rule_scheduled" "classes_autorun_keys_modification" {
  name                       = "classes_autorun_keys_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Classes Autorun Keys Modification"
  description                = "Detects modification of autostart extensibility point (ASEP) in registry. - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason - Legitimate administrator sets up autorun keys for legitimate reason"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\Software\\Classes" and (RegistryKey contains "\\Folder\\ShellEx\\ExtShellFolderViews" or RegistryKey contains "\\Folder\\ShellEx\\DragDropHandlers" or RegistryKey contains "\\Folder\\Shellex\\ColumnHandlers" or RegistryKey contains "\\Filter" or RegistryKey contains "\\Exefile\\Shell\\Open\\Command\\(Default)" or RegistryKey contains "\\Directory\\Shellex\\DragDropHandlers" or RegistryKey contains "\\Directory\\Shellex\\CopyHookHandlers" or RegistryKey contains "\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance" or RegistryKey contains "\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance" or RegistryKey contains "\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance" or RegistryKey contains "\\CLSID\\{083863F1-70DE-11d0-BD40-00A0C911CE86}\\Instance" or RegistryKey contains "\\Classes\\AllFileSystemObjects\\ShellEx\\DragDropHandlers" or RegistryKey contains "\\.exe" or RegistryKey contains "\\.cmd" or RegistryKey contains "\\ShellEx\\PropertySheetHandlers" or RegistryKey contains "\\ShellEx\\ContextMenuHandlers")) and (not((InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\drvinst.exe" or RegistryValueData =~ "(Empty)" or isnull(RegistryValueData) or (InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\svchost.exe" and RegistryKey endswith "\\lnkfile\\shellex\\ContextMenuHandlers*")))) and (not(RegistryValueData =~ "{807583E5-5146-11D5-A672-00B0D022E945}"))
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