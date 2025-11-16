resource "azurerm_sentinel_alert_rule_scheduled" "potential_devil_bait_related_indicator" {
  name                       = "potential_devil_bait_related_indicator"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Devil Bait Related Indicator"
  description                = "Detects the creation of \".xml\" and \".txt\" files in folders of the \"\\AppData\\Roaming\\Microsoft\" directory by uncommon processes. This behavior was seen common across different Devil Bait samples and stages as described by the NCSC - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\schtasks.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe") and FolderPath contains "\\AppData\\Roaming\\Microsoft\\" and (FolderPath endswith ".txt" or FolderPath endswith ".xml")
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