resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_desktop_background_change_using_reg_exe" {
  name                       = "potentially_suspicious_desktop_background_change_using_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Desktop Background Change Using Reg.EXE"
  description                = "Detects the execution of \"reg.exe\" to alter registry keys that would replace the user's desktop background. This is a common technique used by malware to change the desktop background to a ransom note or other image. - Administrative scripts that change the desktop background to a company logo or other image."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "add" and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe")) and (ProcessCommandLine contains "Control Panel\\Desktop" or ProcessCommandLine contains "CurrentVersion\\Policies\\ActiveDesktop" or ProcessCommandLine contains "CurrentVersion\\Policies\\System") and ((ProcessCommandLine contains "/v NoChangingWallpaper" and ProcessCommandLine contains "/d 1") or (ProcessCommandLine contains "/v Wallpaper" and ProcessCommandLine contains "/t REG_SZ") or (ProcessCommandLine contains "/v WallpaperStyle" and ProcessCommandLine contains "/d 2"))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}