resource "azurerm_sentinel_alert_rule_scheduled" "dbghelp_dbgcore_dll_loaded_by_uncommon_suspicious_process" {
  name                       = "dbghelp_dbgcore_dll_loaded_by_uncommon_suspicious_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Dbghelp/Dbgcore DLL Loaded By Uncommon/Suspicious Process"
  description                = "Detects the load of dbghelp/dbgcore DLL by a potentially uncommon or potentially suspicious process. The Dbghelp and Dbgcore DLLs export functions that allow for the dump of process memory. Tools like ProcessHacker, Task Manager and some attacker tradecraft use the MiniDumpWriteDump API found in dbghelp.dll or dbgcore.dll. As an example, SilentTrynity C2 Framework has a module that leverages this API to dump the contents of Lsass.exe and transfer it over the network back to the attacker's machine. Keep in mind that many legitimate Windows processes and services might load the aforementioned DLLs for debugging or other related purposes. Investigate the CommandLine and the Image location of the process loading the DLL. - Debugging scripts might leverage this DLL in order to dump process memory for further analysis."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where ((FolderPath endswith "\\dbghelp.dll" or FolderPath endswith "\\dbgcore.dll") and (InitiatingProcessFolderPath endswith "\\bash.exe" or InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\dnx.exe" or InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\monitoringhost.exe" or InitiatingProcessFolderPath endswith "\\msbuild.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\regsvcs.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\sc.exe" or InitiatingProcessFolderPath endswith "\\scriptrunner.exe" or InitiatingProcessFolderPath endswith "\\winword.exe" or InitiatingProcessFolderPath endswith "\\wmic.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe")) and (not((((InitiatingProcessCommandLine endswith "-k LocalServiceNetworkRestricted" or InitiatingProcessCommandLine endswith "-k WerSvcGroup") and InitiatingProcessFolderPath endswith "\\svchost.exe") or ((InitiatingProcessCommandLine contains "/d srrstr.dll,ExecuteScheduledSPPCreation" or InitiatingProcessCommandLine contains "aepdu.dll,AePduRunUpdate" or InitiatingProcessCommandLine contains "shell32.dll,OpenAs_RunDL" or InitiatingProcessCommandLine contains "Windows.Storage.ApplicationData.dll,CleanupTemporaryState") and InitiatingProcessFolderPath endswith "\\rundll32.exe") or (InitiatingProcessCommandLine endswith "\\TiWorker.exe -Embedding" and InitiatingProcessCommandLine startswith "C:\\WINDOWS\\WinSxS\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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