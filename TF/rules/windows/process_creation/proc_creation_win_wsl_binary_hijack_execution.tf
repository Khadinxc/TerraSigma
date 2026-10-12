resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_wsl_binary_hijack_execution" {
  name                       = "proc_creation_win_wsl_binary_hijack_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious WSL Binary Hijack via Proxy Execution"
  description                = <<DESC
    Detects C:\Windows\System32\wsl.exe spawning a child wsl.exe process from outside the legitimate WSL install locations. When WSL or bash is invoked, the System32 stub (wsl.exe) looks up the InstallLocation registry key and executes the wsl.exe found there. An attacker who modifies InstallLocation to a controlled path causes the stub to transparently proxy execution to a malicious payload, which then appears as a wsl.exe child of the legitimate System32 stub.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wsl_binary_hijack_execution.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\wsl.exe" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\wsl.exe") and (not(((FolderPath in~ ("C:\\Windows\\System32\\wsl.exe", "C:\\Program Files\\WSL\\wsl.exe")) or (FolderPath startswith "C:\\Windows\\WinSxS\\amd64_microsoft-windows-lxss-wsl_" or FolderPath startswith "C:\\Windows\\WinSxS\\arm64_microsoft-windows-lxss-wsl_" or FolderPath startswith "C:\\Program Files\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux") or (FolderPath contains "\\AppData\\Local\\Microsoft\\WindowsApps\\" and FolderPath startswith "C:\\Users\\"))))
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