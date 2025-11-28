resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_desktop_background_change_via_registry" {
  name                       = "potentially_suspicious_desktop_background_change_via_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Desktop Background Change Via Registry"
  description                = "Detects registry value settings that would replace the user's desktop background. This is a common technique used by malware to change the desktop background to a ransom note or other image. - Administrative scripts that change the desktop background to a company logo or other image."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "Control Panel\\Desktop" or RegistryKey contains "CurrentVersion\\Policies\\ActiveDesktop" or RegistryKey contains "CurrentVersion\\Policies\\System") and ((RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey endswith "NoChangingWallpaper") or RegistryKey endswith "\\Wallpaper" or (RegistryValueData =~ "2" and RegistryKey endswith "\\WallpaperStyle")) and (not(((RegistryValueData =~ "(Empty)" and RegistryKey endswith "\\Control Panel\\Desktop\\Wallpaper") or InitiatingProcessFolderPath endswith "C:\\Windows\\Explorer.EXE" or InitiatingProcessFolderPath endswith "\\svchost.exe"))) and (not(((InitiatingProcessFolderPath in~ ("C:\\Program Files\\Amazon\\EC2Launch\\EC2Launch.exe", "C:\\Program Files (x86)\\Amazon\\EC2Launch\\EC2Launch.exe")) and RegistryKey endswith "\\Control Panel\\Desktop\\Wallpaper")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "Impact"]
  techniques                 = ["T1112", "T1491"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}