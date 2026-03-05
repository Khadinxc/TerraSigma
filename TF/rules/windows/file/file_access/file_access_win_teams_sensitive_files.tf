resource "azurerm_sentinel_alert_rule_scheduled" "file_access_win_teams_sensitive_files" {
  name                       = "file_access_win_teams_sensitive_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Microsoft Teams Sensitive File Access By Uncommon Applications"
  description                = <<DESC
    Detects file access attempts to sensitive Microsoft teams files (leveldb, cookies) by an uncommon process.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_access/file_access_win_teams_sensitive_files.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FileName contains "\\Microsoft\\Teams\\Cookies" or FileName contains "\\Microsoft\\Teams\\Local Storage\\leveldb") and (not(InitiatingProcessFolderPath endswith "\\Microsoft\\Teams\\current\\Teams.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1528"]
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