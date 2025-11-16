resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_binaries_and_scripts_in_public_folder" {
  name                       = "suspicious_binaries_and_scripts_in_public_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Binaries and Scripts in Public Folder"
  description                = "Detects the creation of a file with a suspicious extension in the public folder, which could indicate potential malicious activity. - Administrators deploying legitimate binaries to public folders."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains ":\\Users\\Public\\" and (FolderPath endswith ".bat" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".js" or FolderPath endswith ".ps1" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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