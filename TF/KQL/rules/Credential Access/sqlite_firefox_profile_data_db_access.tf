resource "azurerm_sentinel_alert_rule_scheduled" "sqlite_firefox_profile_data_db_access" {
  name                       = "sqlite_firefox_profile_data_db_access"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SQLite Firefox Profile Data DB Access"
  description                = "Detect usage of the \"sqlite\" binary to query databases in Firefox and other Gecko-based browsers for potential data stealing."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "cookies.sqlite" or ProcessCommandLine contains "places.sqlite") and (ProcessVersionInfoProductName =~ "SQLite" or (FolderPath endswith "\\sqlite.exe" or FolderPath endswith "\\sqlite3.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "Collection"]
  techniques                 = ["T1539", "T1005"]
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