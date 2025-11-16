resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_cabinet_file_expansion" {
  name                       = "potentially_suspicious_cabinet_file_expansion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Cabinet File Expansion"
  description                = "Detects the expansion or decompression of cabinet files from potentially suspicious or uncommon locations, e.g. seen in Iranian MeteorExpress related attacks - System administrator Usage"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "-F:" or ProcessCommandLine contains "/F:" or ProcessCommandLine contains "–F:" or ProcessCommandLine contains "—F:" or ProcessCommandLine contains "―F:") and FolderPath endswith "\\expand.exe") and ((ProcessCommandLine contains ":\\Perflogs\\" or ProcessCommandLine contains ":\\ProgramData" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\Admin$\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\AppData\\Roaming\\" or ProcessCommandLine contains "\\C$\\" or ProcessCommandLine contains "\\Temporary Internet") or ((ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Favorites\\") or (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Favourites\\") or (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Contacts\\"))) and (not((ProcessCommandLine contains "C:\\ProgramData\\Dell\\UpdateService\\Temp\\" and InitiatingProcessFolderPath =~ "C:\\Program Files (x86)\\Dell\\UpdateService\\ServiceShell.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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