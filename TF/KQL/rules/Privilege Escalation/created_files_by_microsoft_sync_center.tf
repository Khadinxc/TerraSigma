resource "azurerm_sentinel_alert_rule_scheduled" "created_files_by_microsoft_sync_center" {
  name                       = "created_files_by_microsoft_sync_center"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Created Files by Microsoft Sync Center"
  description                = "This rule detects suspicious files created by Microsoft Sync Center (mobsync)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\mobsync.exe" and (FolderPath endswith ".dll" or FolderPath endswith ".exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "DefenseEvasion"]
  techniques                 = ["T1055", "T1218"]
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