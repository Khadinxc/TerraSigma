resource "azurerm_sentinel_alert_rule_scheduled" "diamond_sleet_apt_file_creation_indicators" {
  name                       = "diamond_sleet_apt_file_creation_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Diamond Sleet APT File Creation Indicators"
  description                = "Detects file creation activity that is related to Diamond Sleet APT activity - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ":\\ProgramData\\4800-84DC-063A6A41C5C" or FolderPath endswith ":\\ProgramData\\clip.exe" or FolderPath endswith ":\\ProgramData\\DSROLE.dll" or FolderPath endswith ":\\ProgramData\\Forest64.exe" or FolderPath endswith ":\\ProgramData\\readme.md" or FolderPath endswith ":\\ProgramData\\Version.dll" or FolderPath endswith ":\\ProgramData\\wsmprovhost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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