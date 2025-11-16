resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_script_execution_from_temp_folder" {
  name                       = "suspicious_script_execution_from_temp_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Script Execution From Temp Folder"
  description                = "Detects a suspicious script executions from temporary folder - Administrative scripts"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\Windows\\Temp" or ProcessCommandLine contains "\\Temporary Internet" or ProcessCommandLine contains "\\AppData\\Local\\Temp" or ProcessCommandLine contains "\\AppData\\Roaming\\Temp" or ProcessCommandLine contains "%TEMP%" or ProcessCommandLine contains "%TMP%" or ProcessCommandLine contains "%LocalAppData%\\Temp") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe")) and (not((ProcessCommandLine contains " >" or ProcessCommandLine contains "Out-File" or ProcessCommandLine contains "ConvertTo-Json" or ProcessCommandLine contains "-WindowStyle hidden -Verb runAs" or ProcessCommandLine contains "\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp\\Amazon\\EC2-Windows\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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