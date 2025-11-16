resource "azurerm_sentinel_alert_rule_scheduled" "cscript_wscript_uncommon_script_extension_execution" {
  name                       = "cscript_wscript_uncommon_script_extension_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cscript/Wscript Uncommon Script Extension Execution"
  description                = "Detects Wscript/Cscript executing a file with an uncommon (i.e. non-script) extension"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".csv" or ProcessCommandLine contains ".dat" or ProcessCommandLine contains ".doc" or ProcessCommandLine contains ".gif" or ProcessCommandLine contains ".jpeg" or ProcessCommandLine contains ".jpg" or ProcessCommandLine contains ".png" or ProcessCommandLine contains ".ppt" or ProcessCommandLine contains ".txt" or ProcessCommandLine contains ".xls" or ProcessCommandLine contains ".xml") and ((ProcessVersionInfoOriginalFileName in~ ("wscript.exe", "cscript.exe")) or (FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe"))
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}