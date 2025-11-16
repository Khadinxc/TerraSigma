resource "azurerm_sentinel_alert_rule_scheduled" "adexplorer_writing_complete_ad_snapshot_into_dat_file" {
  name                       = "adexplorer_writing_complete_ad_snapshot_into_dat_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ADExplorer Writing Complete AD Snapshot Into .dat File"
  description                = "Detects the dual use tool ADExplorer writing a complete AD snapshot into a .dat file. This can be used by attackers to extract data for Bloodhound, usernames for password spraying or use the meta data for social engineering. The snapshot doesn't contain password hashes but there have been cases, where administrators put passwords in the comment field. - Legitimate use of ADExplorer by administrators creating .dat snapshots"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\ADExp.exe" or InitiatingProcessFolderPath endswith "\\ADExplorer.exe" or InitiatingProcessFolderPath endswith "\\ADExplorer64.exe" or InitiatingProcessFolderPath endswith "\\ADExplorer64a.exe") and FolderPath endswith ".dat"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1087", "T1069", "T1482"]
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