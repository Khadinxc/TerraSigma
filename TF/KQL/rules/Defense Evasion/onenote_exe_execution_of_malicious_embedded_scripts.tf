resource "azurerm_sentinel_alert_rule_scheduled" "onenote_exe_execution_of_malicious_embedded_scripts" {
  name                       = "onenote_exe_execution_of_malicious_embedded_scripts"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OneNote.EXE Execution of Malicious Embedded Scripts"
  description                = "Detects the execution of malicious OneNote documents that contain embedded scripts. When a user clicks on a OneNote attachment and then on the malicious link inside the \".one\" file, it exports and executes the malicious embedded script from specific directories. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\exported\\" or ProcessCommandLine contains "\\onenoteofflinecache_files\\") and (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wscript.exe") and InitiatingProcessFolderPath endswith "\\onenote.exe"
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