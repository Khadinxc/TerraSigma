resource "azurerm_sentinel_alert_rule_scheduled" "file_delete_win_delete_backup_file" {
  name                       = "file_delete_win_delete_backup_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Backup Files Deleted"
  description                = <<DESC
    Detects deletion of files with extensions often used for backup files. Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_delete/file_delete_win_delete_backup_file.yml

    False Positives:
    - Legitimate usage
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\wt.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe") and (FolderPath endswith ".VHD" or FolderPath endswith ".bac" or FolderPath endswith ".bak" or FolderPath endswith ".wbcat" or FolderPath endswith ".bkf" or FolderPath endswith ".set" or FolderPath endswith ".win" or FolderPath endswith ".dsk")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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