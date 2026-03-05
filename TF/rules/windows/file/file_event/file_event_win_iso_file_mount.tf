resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_iso_file_mount" {
  name                       = "file_event_win_iso_file_mount"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ISO File Created Within Temp Folders"
  description                = <<DESC
    Detects the creation of a ISO file in the Outlook temp folder or in the Appdata temp folder. Typical of Qakbot TTP from end-July 2022.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_iso_file_mount.yml

    False Positives:
    - Potential FP by sysadmin opening a zip file containing a legitimate ISO file
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where ((FolderPath contains "\\AppData\\Local\\Temp\\" and FolderPath contains ".zip\\") and FolderPath endswith ".iso") or (FolderPath contains "\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\" and FolderPath endswith ".iso")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1566"]
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