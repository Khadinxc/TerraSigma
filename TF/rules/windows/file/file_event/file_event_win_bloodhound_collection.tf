resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_bloodhound_collection" {
  name                       = "file_event_win_bloodhound_collection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "BloodHound Collection Files"
  description                = <<DESC
    Detects default file names outputted by the BloodHound collection tool SharpHound

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_bloodhound_collection.yml

    False Positives:
    - Some false positives may arise in some environment and this may require some tuning. Add additional filters or reduce level depending on the level of noise
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "BloodHound.zip" or FolderPath endswith "_computers.json" or FolderPath endswith "_containers.json" or FolderPath endswith "_gpos.json" or FolderPath endswith "_groups.json" or FolderPath endswith "_ous.json" or FolderPath endswith "_users.json") and (not((InitiatingProcessFolderPath endswith "\\svchost.exe" and FolderPath endswith "\\pocket_containers.json" and FolderPath startswith "C:\\Program Files\\WindowsApps\\Microsoft.")))
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