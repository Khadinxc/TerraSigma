resource "azurerm_sentinel_alert_rule_scheduled" "prefetch_file_deleted" {
  name                       = "prefetch_file_deleted"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Prefetch File Deleted"
  description                = "Detects the deletion of a prefetch file which may indicate an attempt to destroy forensic evidence"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains ":\\Windows\\Prefetch\\" and FolderPath endswith ".pf") and (not((InitiatingProcessFolderPath endswith ":\\windows\\system32\\svchost.exe" and (RequestAccountName contains "AUTHORI" or RequestAccountName contains "AUTORI"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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