resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_dump_file_creation" {
  name                       = "file_event_win_dump_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DMP/HDMP File Creation"
  description                = <<DESC
    Detects the creation of a file with the ".dmp"/".hdmp" extension. Often created by software during a crash. Memory dumps can sometimes contain sensitive information such as credentials. It's best to determine the source of the crash.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/file/file_event/file_event_win_dump_file_creation.yml

    False Positives:
    - Likely during crashes of software
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".dmp" or FolderPath endswith ".dump" or FolderPath endswith ".hdmp"
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