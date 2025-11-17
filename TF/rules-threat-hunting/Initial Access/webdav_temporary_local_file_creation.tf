resource "azurerm_sentinel_alert_rule_scheduled" "webdav_temporary_local_file_creation" {
  name                       = "webdav_temporary_local_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WebDAV Temporary Local File Creation"
  description                = "Detects the creation of WebDAV temporary files with potentially suspicious extensions - Legitimate use of WebDAV in an environment"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "\\AppData\\Local\\Temp\\TfsStore\\Tfs_DAV\\" and (FolderPath endswith ".7z" or FolderPath endswith ".bat" or FolderPath endswith ".dat" or FolderPath endswith ".ico" or FolderPath endswith ".js" or FolderPath endswith ".lnk" or FolderPath endswith ".ps1" or FolderPath endswith ".rar" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs" or FolderPath endswith ".zip")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "ResourceDevelopment"]
  techniques                 = ["T1584", "T1566"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}