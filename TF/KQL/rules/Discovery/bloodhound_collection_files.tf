resource "azurerm_sentinel_alert_rule_scheduled" "bloodhound_collection_files" {
  name                       = "bloodhound_collection_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "BloodHound Collection Files"
  description                = "Detects default file names outputted by the BloodHound collection tool SharpHound - Some false positives may arise in some environment and this may require some tuning. Add additional filters or reduce level depending on the level of noise"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "BloodHound.zip" or FolderPath endswith "_computers.json" or FolderPath endswith "_containers.json" or FolderPath endswith "_domains.json" or FolderPath endswith "_gpos.json" or FolderPath endswith "_groups.json" or FolderPath endswith "_ous.json" or FolderPath endswith "_users.json") and (not((InitiatingProcessFolderPath endswith "\\svchost.exe" and FolderPath endswith "\\pocket_containers.json" and FolderPath startswith "C:\\Program Files\\WindowsApps\\Microsoft.")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "Execution"]
  techniques                 = ["T1087", "T1482", "T1069", "T1059"]
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