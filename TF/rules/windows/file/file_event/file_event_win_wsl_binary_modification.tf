resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_wsl_binary_modification" {
  name                       = "file_event_win_wsl_binary_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential WSL Binary Modification from Installed Location"
  description                = <<DESC
    Detects the modification of the wsl.exe binary from its installed location. Attackers can replace the legitimate wsl.exe binary with a malicious payload in its place, which is then executed when the user runs WSL, acting as a proxy execution and defense evasion technique.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_wsl_binary_modification.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "\\wsl.exe" and ((FolderPath contains ":\\Program files\\wsl\\" or FolderPath contains ":\\Program files\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_") or (FolderPath contains ":\\Users\\" and FolderPath contains "\\AppData\\Local\\Microsoft\\WindowsApps\\"))) and (not(((InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")) or (InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\svchost.exe" and FolderPath contains "\\WindowsApps\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  techniques                 = ["T1036", "T1218"]
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