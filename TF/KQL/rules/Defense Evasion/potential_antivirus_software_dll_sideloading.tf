resource "azurerm_sentinel_alert_rule_scheduled" "potential_antivirus_software_dll_sideloading" {
  name                       = "potential_antivirus_software_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Antivirus Software DLL Sideloading"
  description                = "Detects potential DLL sideloading of DLLs that are part of antivirus software suchas McAfee, Symantec...etc - Applications that load the same dlls mentioned in the detection section. Investigate them and filter them out if a lot FPs are caused. - Dell SARemediation plugin folder (C:\\Program Files\\Dell\\SARemediation\\plugin\\log.dll) is known to contain the 'log.dll' file. - The Canon MyPrinter folder 'C:\\Program Files\\Canon\\MyPrinter\\' is known to contain the 'log.dll' file"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\log.dll" and (not(((FolderPath in~ ("C:\\Program Files\\AVAST Software\\Avast\\log.dll", "C:\\Program Files (x86)\\AVAST Software\\Avast\\log.dll")) or (FolderPath in~ ("C:\\Program Files\\AVG\\Antivirus\\log.dll", "C:\\Program Files (x86)\\AVG\\Antivirus\\log.dll")) or (FolderPath startswith "C:\\Program Files\\Bitdefender Antivirus Free\\" or FolderPath startswith "C:\\Program Files (x86)\\Bitdefender Antivirus Free\\") or FolderPath startswith "C:\\Program Files\\Canon\\MyPrinter\\" or (InitiatingProcessFolderPath =~ "C:\\Program Files\\Dell\\SARemediation\\audit\\TelemetryUtility.exe" and (FolderPath in~ ("C:\\Program Files\\Dell\\SARemediation\\plugin\\log.dll", "C:\\Program Files\\Dell\\SARemediation\\audit\\log.dll"))))))) or (FolderPath endswith "\\qrt.dll" and (not((FolderPath startswith "C:\\Program Files\\F-Secure\\Anti-Virus\\" or FolderPath startswith "C:\\Program Files (x86)\\F-Secure\\Anti-Virus\\")))) or ((FolderPath endswith "\\ashldres.dll" or FolderPath endswith "\\lockdown.dll" or FolderPath endswith "\\vsodscpl.dll") and (not((FolderPath startswith "C:\\Program Files\\McAfee\\" or FolderPath startswith "C:\\Program Files (x86)\\McAfee\\")))) or (FolderPath endswith "\\vftrace.dll" and (not((FolderPath startswith "C:\\Program Files\\CyberArk\\Endpoint Privilege Manager\\Agent\\x32\\" or FolderPath startswith "C:\\Program Files (x86)\\CyberArk\\Endpoint Privilege Manager\\Agent\\x32\\")))) or (FolderPath endswith "\\wsc.dll" and (not(((FolderPath startswith "C:\\program Files\\AVAST Software\\Avast\\" or FolderPath startswith "C:\\program Files (x86)\\AVAST Software\\Avast\\") or (FolderPath startswith "C:\\Program Files\\AVG\\Antivirus\\" or FolderPath startswith "C:\\Program Files (x86)\\AVG\\Antivirus\\"))))) or (FolderPath endswith "\\tmdbglog.dll" and (not((FolderPath startswith "C:\\program Files\\Trend Micro\\Titanium\\" or FolderPath startswith "C:\\program Files (x86)\\Trend Micro\\Titanium\\")))) or (FolderPath endswith "\\DLPPREM32.dll" and (not((FolderPath startswith "C:\\program Files\\ESET" or FolderPath startswith "C:\\program Files (x86)\\ESET"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}