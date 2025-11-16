resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_filesystem_load_attempt_by_format_com" {
  name                       = "uncommon_filesystem_load_attempt_by_format_com"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon FileSystem Load Attempt By Format.com"
  description                = "Detects the execution of format.com with an uncommon filesystem selection that could indicate a defense evasion activity in which \"format.com\" is used to load malicious DLL files or other programs."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/fs:" and FolderPath endswith "\\format.com") and (not((ProcessCommandLine contains "/fs:exFAT" or ProcessCommandLine contains "/fs:FAT" or ProcessCommandLine contains "/fs:NTFS" or ProcessCommandLine contains "/fs:ReFS" or ProcessCommandLine contains "/fs:UDF")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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