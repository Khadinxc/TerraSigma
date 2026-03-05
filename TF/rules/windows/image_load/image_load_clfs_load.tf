resource "azurerm_sentinel_alert_rule_scheduled" "image_load_clfs_load" {
  name                       = "image_load_clfs_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Clfs.SYS Loaded By Process Located In a Potential Suspicious Location"
  description                = <<DESC
    Detects Clfs.sys being loaded by a process running from a potentially suspicious location. Clfs.sys is loaded as part of many CVEs exploits that targets Common Log File.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_clfs_load.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\clfs.sys" and ((InitiatingProcessFolderPath contains ":\\Perflogs\\" or InitiatingProcessFolderPath contains ":\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\Temporary Internet" or InitiatingProcessFolderPath contains "\\Windows\\Temp\\") or ((InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Favorites\\") or (InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Favourites\\") or (InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Contacts\\") or (InitiatingProcessFolderPath contains ":\\Users\\" and InitiatingProcessFolderPath contains "\\Pictures\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}