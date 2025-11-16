resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_active_directory_database_snapshot_via_adexplorer" {
  name                       = "suspicious_active_directory_database_snapshot_via_adexplorer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Active Directory Database Snapshot Via ADExplorer"
  description                = "Detects the execution of Sysinternals ADExplorer with the \"-snapshot\" flag in order to save a local copy of the active directory database to a suspicious directory. This can be used by attackers to extract data for Bloodhound, usernames for password spraying or use the meta data for social engineering. The snapshot doesn't contain password hashes but there have been cases, where administrators put passwords in the comment field."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "snapshot" and ((FolderPath endswith "\\ADExp.exe" or FolderPath endswith "\\ADExplorer.exe" or FolderPath endswith "\\ADExplorer64.exe" or FolderPath endswith "\\ADExplorer64a.exe") or ProcessVersionInfoOriginalFileName =~ "AdExp" or ProcessVersionInfoFileDescription =~ "Active Directory Editor" or ProcessVersionInfoProductName =~ "Sysinternals ADExplorer") and (ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\AppData\\" or ProcessCommandLine contains "\\Windows\\Temp\\")
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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