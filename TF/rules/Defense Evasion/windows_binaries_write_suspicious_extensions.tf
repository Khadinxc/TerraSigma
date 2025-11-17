resource "azurerm_sentinel_alert_rule_scheduled" "windows_binaries_write_suspicious_extensions" {
  name                       = "windows_binaries_write_suspicious_extensions"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Binaries Write Suspicious Extensions"
  description                = "Detects Windows executables that write files with suspicious extensions"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (((InitiatingProcessFolderPath endswith "\\csrss.exe" or InitiatingProcessFolderPath endswith "\\lsass.exe" or InitiatingProcessFolderPath endswith "\\RuntimeBroker.exe" or InitiatingProcessFolderPath endswith "\\sihost.exe" or InitiatingProcessFolderPath endswith "\\smss.exe" or InitiatingProcessFolderPath endswith "\\wininit.exe" or InitiatingProcessFolderPath endswith "\\winlogon.exe") and (FolderPath endswith ".bat" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".iso" or FolderPath endswith ".ps1" or FolderPath endswith ".txt" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs")) or ((InitiatingProcessFolderPath endswith "\\dllhost.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\svchost.exe") and (FolderPath endswith ".bat" or FolderPath endswith ".hta" or FolderPath endswith ".iso" or FolderPath endswith ".ps1" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs"))) and (not(((InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\dllhost.exe" and (FolderPath contains ":\\Users\\" and FolderPath contains "\\AppData\\Local\\Temp\\__PSScriptPolicyTest_") and FolderPath endswith ".ps1") or (InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\svchost.exe" and (FolderPath contains "C:\\Program Files\\WindowsApps\\Clipchamp" and FolderPath contains ".ps1")) or ((InitiatingProcessFolderPath in~ ("C:\\Windows\\system32\\svchost.exe", "C:\\Windows\\SysWOW64\\svchost.exe")) and FolderPath endswith ".ps1" and (FolderPath startswith "C:\\Program Files\\WindowsApps\\Microsoft.PowerShellPreview" or FolderPath startswith "C:\\Program Files (x86)\\WindowsApps\\Microsoft.PowerShellPreview")) or (InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\svchost.exe" and (FolderPath contains "C:\\Windows\\System32\\GroupPolicy\\DataStore\\" and FolderPath contains "\\sysvol\\" and FolderPath contains "\\Policies\\" and FolderPath contains "\\Machine\\Scripts\\Startup\\") and (FolderPath endswith ".ps1" or FolderPath endswith ".bat")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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