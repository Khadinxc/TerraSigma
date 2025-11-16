resource "azurerm_sentinel_alert_rule_scheduled" "pikabot_fake_dll_extension_execution_via_rundll32_exe" {
  name                       = "pikabot_fake_dll_extension_execution_via_rundll32_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Pikabot Fake DLL Extension Execution Via Rundll32.EXE"
  description                = "Detects specific process tree behavior linked to \"rundll32\" executions, wherein the associated DLL lacks a common \".dll\" extension, often signaling potential Pikabot activity."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains ":\\ProgramData\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\Installer\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\AppData\\Roaming\\") and FolderPath endswith "\\rundll32.exe" and (InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe")) and (not(((ProcessCommandLine contains ".cpl " or ProcessCommandLine contains ".cpl," or ProcessCommandLine contains ".dll " or ProcessCommandLine contains ".dll," or ProcessCommandLine contains ".inf " or ProcessCommandLine contains ".inf,") or (ProcessCommandLine endswith ".cpl" or ProcessCommandLine endswith ".cpl\"" or ProcessCommandLine endswith ".dll" or ProcessCommandLine endswith ".dll\"" or ProcessCommandLine endswith ".inf" or ProcessCommandLine endswith ".inf\"" or ProcessCommandLine endswith ".cpl'" or ProcessCommandLine endswith ".dll'" or ProcessCommandLine endswith ".inf'"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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
      column_name = "ProcessCommandLine"
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