resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_winrar_file_creation_in_startup_folder" {
  name                       = "file_event_win_winrar_file_creation_in_startup_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WinRAR Creating Files in Startup Locations"
  description                = <<DESC
    Detects WinRAR creating files in Windows startup locations, which may indicate an attempt to establish persistence by adding malicious files to the Startup folder. This kind of behaviour has been associated with exploitation of WinRAR path traversal vulnerability CVE-2025-6218 or CVE-2025-8088.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_winrar_file_creation_in_startup_folder.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\WinRAR.exe" or InitiatingProcessFolderPath endswith "\\Rar.exe") and FolderPath contains "\\Start Menu\\Programs\\Startup\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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