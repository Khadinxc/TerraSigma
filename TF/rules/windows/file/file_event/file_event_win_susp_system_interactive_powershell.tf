resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_susp_system_interactive_powershell" {
  name                       = "file_event_win_susp_system_interactive_powershell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Interactive PowerShell as SYSTEM"
  description                = "Detects the creation of files that indicator an interactive use of PowerShell in the SYSTEM user context Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_system_interactive_powershell.yml - Administrative activity - PowerShell scripts running as SYSTEM user | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_system_interactive_powershell.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath in~ ("C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-Interactive")
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