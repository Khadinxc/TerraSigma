resource "azurerm_sentinel_alert_rule_scheduled" "access_to_reg_hive_files_by_uncommon_applications" {
  name                       = "access_to_reg_hive_files_by_uncommon_applications"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access To .Reg/.Hive Files By Uncommon Applications"
  description                = "Detects file access requests to files ending with either the \".hive\"/\".reg\" extension, usually associated with Windows Registry backups. - Third party software installed in the user context might generate a lot of FPs. Heavy baselining and tuning might be required."
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where (FileName endswith ".hive" or FileName endswith ".reg") and (not((InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
  techniques                 = ["T1112"]
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