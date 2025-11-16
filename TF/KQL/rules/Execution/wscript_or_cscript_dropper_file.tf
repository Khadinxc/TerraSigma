resource "azurerm_sentinel_alert_rule_scheduled" "wscript_or_cscript_dropper_file" {
  name                       = "wscript_or_cscript_dropper_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WScript or CScript Dropper - File"
  description                = "Detects a file ending in jse, vbe, js, vba, vbs written by cscript.exe or wscript.exe"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\wscript.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe") and (FolderPath endswith ".jse" or FolderPath endswith ".vbe" or FolderPath endswith ".js" or FolderPath endswith ".vba" or FolderPath endswith ".vbs") and (FolderPath startswith "C:\\Users\\" or FolderPath startswith "C:\\ProgramData")
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