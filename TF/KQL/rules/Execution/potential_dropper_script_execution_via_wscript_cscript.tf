resource "azurerm_sentinel_alert_rule_scheduled" "potential_dropper_script_execution_via_wscript_cscript" {
  name                       = "potential_dropper_script_execution_via_wscript_cscript"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Dropper Script Execution Via WScript/CScript"
  description                = "Detects wscript/cscript executions of scripts located in user directories - Some installers might generate a similar behavior. An initial baseline is required"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe") and (ProcessCommandLine contains ".js" or ProcessCommandLine contains ".jse" or ProcessCommandLine contains ".vba" or ProcessCommandLine contains ".vbe" or ProcessCommandLine contains ".vbs" or ProcessCommandLine contains ".wsf") and (ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Tmp\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\")
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