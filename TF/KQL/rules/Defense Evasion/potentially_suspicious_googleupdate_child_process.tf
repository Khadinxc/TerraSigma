resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_googleupdate_child_process" {
  name                       = "potentially_suspicious_googleupdate_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious GoogleUpdate Child Process"
  description                = "Detects potentially suspicious child processes of \"GoogleUpdate.exe\""
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\GoogleUpdate.exe" and (not((isnull(FolderPath) or (FolderPath contains "\\Google" or (FolderPath endswith "\\setup.exe" or FolderPath endswith "chrome_updater.exe" or FolderPath endswith "chrome_installer.exe")))))
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