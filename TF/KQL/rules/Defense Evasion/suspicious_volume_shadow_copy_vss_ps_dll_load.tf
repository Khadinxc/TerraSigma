resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_volume_shadow_copy_vss_ps_dll_load" {
  name                       = "suspicious_volume_shadow_copy_vss_ps_dll_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Volume Shadow Copy VSS_PS.dll Load"
  description                = "Detects the image load of vss_ps.dll by uncommon executables. This DLL is used by the Volume Shadow Copy Service (VSS) to manage shadow copies of files and volumes. It is often abused by attackers to delete or manipulate shadow copies, which can hinder forensic investigations and data recovery efforts. The fact that it is loaded by processes that are not typically associated with VSS operations can indicate suspicious activity."
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\vss_ps.dll" and (not((isnull(InitiatingProcessFolderPath) or ((InitiatingProcessFolderPath endswith "\\clussvc.exe" or InitiatingProcessFolderPath endswith "\\dismhost.exe" or InitiatingProcessFolderPath endswith "\\dllhost.exe" or InitiatingProcessFolderPath endswith "\\inetsrv\\appcmd.exe" or InitiatingProcessFolderPath endswith "\\inetsrv\\iissetup.exe" or InitiatingProcessFolderPath endswith "\\msiexec.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\searchindexer.exe" or InitiatingProcessFolderPath endswith "\\srtasks.exe" or InitiatingProcessFolderPath endswith "\\svchost.exe" or InitiatingProcessFolderPath endswith "\\System32\\SystemPropertiesAdvanced.exe" or InitiatingProcessFolderPath endswith "\\taskhostw.exe" or InitiatingProcessFolderPath endswith "\\thor.exe" or InitiatingProcessFolderPath endswith "\\thor64.exe" or InitiatingProcessFolderPath endswith "\\tiworker.exe" or InitiatingProcessFolderPath endswith "\\vssvc.exe" or InitiatingProcessFolderPath endswith "\\vssadmin.exe" or InitiatingProcessFolderPath endswith "\\WmiPrvSE.exe" or InitiatingProcessFolderPath endswith "\\wsmprovhost.exe") and InitiatingProcessFolderPath startswith "C:\\Windows\\") or (InitiatingProcessCommandLine contains "\\dismhost.exe {" and InitiatingProcessCommandLine startswith "C:\\$WinREAgent\\Scratch\\")))) and (not((InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Impact"]
  techniques                 = ["T1490"]
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
      identifier  = "CommandLine"
      column_name = "InitiatingProcessCommandLine"
    }
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