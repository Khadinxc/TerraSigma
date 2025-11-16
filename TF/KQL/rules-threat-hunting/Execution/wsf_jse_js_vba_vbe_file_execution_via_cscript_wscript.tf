resource "azurerm_sentinel_alert_rule_scheduled" "wsf_jse_js_vba_vbe_file_execution_via_cscript_wscript" {
  name                       = "wsf_jse_js_vba_vbe_file_execution_via_cscript_wscript"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript"
  description                = "Detects script file execution (.js, .jse, .vba, .vbe, .vbs, .wsf) by Wscript/Cscript - Some additional tuning is required. It is recommended to add the user profile path in CommandLine if it is getting too noisy."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".js" or ProcessCommandLine contains ".jse" or ProcessCommandLine contains ".vba" or ProcessCommandLine contains ".vbe" or ProcessCommandLine contains ".vbs" or ProcessCommandLine contains ".wsf") and ((ProcessVersionInfoOriginalFileName in~ ("wscript.exe", "cscript.exe")) or (FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe"))
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