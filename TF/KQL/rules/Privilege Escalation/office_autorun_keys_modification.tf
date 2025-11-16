resource "azurerm_sentinel_alert_rule_scheduled" "office_autorun_keys_modification" {
  name                       = "office_autorun_keys_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Office Autorun Keys Modification"
  description                = "Detects modification of autostart extensibility point (ASEP) in registry. - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason - Legitimate administrator sets up autorun keys for legitimate reason"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey contains "\\Word\\Addins" or RegistryKey contains "\\PowerPoint\\Addins" or RegistryKey contains "\\Outlook\\Addins" or RegistryKey contains "\\Onenote\\Addins" or RegistryKey contains "\\Excel\\Addins" or RegistryKey contains "\\Access\\Addins" or RegistryKey contains "test\\Special\\Perf") and (RegistryKey contains "\\Software\\Wow6432Node\\Microsoft\\Office" or RegistryKey contains "\\Software\\Microsoft\\Office")) and (not((RegistryValueData =~ "(Empty)" or ((InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft Office\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft Office\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\msiexec.exe" or InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\regsvr32.exe") and (RegistryKey endswith "\\Excel\\Addins\\AdHocReportingExcelClientLib.AdHocReportingExcelClientAddIn.1*" or RegistryKey endswith "\\Excel\\Addins\\ExcelPlugInShell.PowerMapConnect*" or RegistryKey endswith "\\Excel\\Addins\\NativeShim*" or RegistryKey endswith "\\Excel\\Addins\\NativeShim.InquireConnector.1*" or RegistryKey endswith "\\Excel\\Addins\\PowerPivotExcelClientAddIn.NativeEntry.1*" or RegistryKey endswith "\\Outlook\\AddIns\\AccessAddin.DC*" or RegistryKey endswith "\\Outlook\\AddIns\\ColleagueImport.ColleagueImportAddin*" or RegistryKey endswith "\\Outlook\\AddIns\\EvernoteCC.EvernoteContactConnector*" or RegistryKey endswith "\\Outlook\\AddIns\\EvernoteOLRD.Connect*" or RegistryKey endswith "\\Outlook\\Addins\\Microsoft.VbaAddinForOutlook.1*" or RegistryKey endswith "\\Outlook\\Addins\\OcOffice.OcForms*" or RegistryKey contains "\\Outlook\\Addins\\OneNote.OutlookAddin" or RegistryKey endswith "\\Outlook\\Addins\\OscAddin.Connect*" or RegistryKey endswith "\\Outlook\\Addins\\OutlookChangeNotifier.Connect*" or RegistryKey contains "\\Outlook\\Addins\\UCAddin.LyncAddin.1" or RegistryKey contains "\\Outlook\\Addins\\UCAddin.UCAddin.1" or RegistryKey endswith "\\Outlook\\Addins\\UmOutlookAddin.FormRegionAddin*" or RegistryKey contains "AddinTakeNotesService\\FriendlyName")) or (InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\Updates\\"))))) and (not((((InitiatingProcessFolderPath in~ ("C:\\Program Files\\Avast Software\\Avast\\RegSvr.exe", "C:\\Program Files\\Avast Software\\Avast\\x86\\RegSvr.exe")) and RegistryKey endswith "\\Microsoft\\Office\\Outlook\\Addins\\Avast.AsOutExt*") or ((InitiatingProcessFolderPath in~ ("C:\\Program Files\\AVG\\Antivirus\\RegSvr.exe", "C:\\Program Files\\AVG\\Antivirus\\x86\\RegSvr.exe")) and RegistryKey endswith "\\Microsoft\\Office\\Outlook\\Addins\\Antivirus.AsOutExt*"))))
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