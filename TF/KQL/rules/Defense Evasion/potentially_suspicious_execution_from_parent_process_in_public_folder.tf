resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_execution_from_parent_process_in_public_folder" {
  name                       = "potentially_suspicious_execution_from_parent_process_in_public_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Execution From Parent Process In Public Folder"
  description                = "Detects a potentially suspicious execution of a parent process located in the \"\\Users\\Public\" folder executing a child process containing references to shell or scripting binaries and commandlines."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\wscript.exe") or (ProcessCommandLine contains "bitsadmin" or ProcessCommandLine contains "certutil" or ProcessCommandLine contains "cscript" or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "powershell" or ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "wscript")) and InitiatingProcessFolderPath contains ":\\Users\\Public\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1564", "T1059"]
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