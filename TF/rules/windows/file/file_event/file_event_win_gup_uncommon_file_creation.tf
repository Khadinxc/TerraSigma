resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_gup_uncommon_file_creation" {
  name                       = "file_event_win_gup_uncommon_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon File Created by Notepad++ Updater Gup.EXE"
  description                = <<DESC
    Detects when the Notepad++ updater (gup.exe) creates files in suspicious or uncommon locations. This could indicate potential exploitation of the updater component to deliver unwanted malware or unwarranted files.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_gup_uncommon_file_creation.yml

    False Positives:
    - Custom or portable Notepad++ installations in non-standard directories.
    - Legitimate update processes creating temporary files in unexpected locations.
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\gup.exe" and (not(((FolderPath startswith "C:\\Program Files\\Notepad++\\" or FolderPath startswith "C:\\Program Files (x86)\\Notepad++\\") or FolderPath startswith "C:\\$Recycle.Bin\\S-1-5-21" or ((FolderPath contains "\\AppData\\Local\\Temp\\" and FolderPath contains ".zip") and FolderPath startswith "C:\\Users\\") or ((FolderPath contains "\\AppData\\Local\\Temp\\" and FolderPath contains "npp." and FolderPath contains ".Installer." and FolderPath contains ".exe") and FolderPath startswith "C:\\Users\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "CredentialAccess", "InitialAccess"]
  techniques                 = ["T1195", "T1557"]
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