resource "azurerm_sentinel_alert_rule_scheduled" "sqlite_chromium_profile_data_db_access" {
  name                       = "sqlite_chromium_profile_data_db_access"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SQLite Chromium Profile Data DB Access"
  description                = "Detect usage of the \"sqlite\" binary to query databases in Chromium-based browsers for potential data stealing."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\User Data\\" or ProcessCommandLine contains "\\Opera Software\\" or ProcessCommandLine contains "\\ChromiumViewer\\") and (ProcessCommandLine contains "Login Data" or ProcessCommandLine contains "Cookies" or ProcessCommandLine contains "Web Data" or ProcessCommandLine contains "History" or ProcessCommandLine contains "Bookmarks") and (ProcessVersionInfoProductName =~ "SQLite" or (FolderPath endswith "\\sqlite.exe" or FolderPath endswith "\\sqlite3.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "Collection"]
  techniques                 = ["T1539", "T1555", "T1005"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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