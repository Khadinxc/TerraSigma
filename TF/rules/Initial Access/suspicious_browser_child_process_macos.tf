resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_browser_child_process_macos" {
  name                       = "suspicious_browser_child_process_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Browser Child Process - MacOS"
  description                = "Detects suspicious child processes spawned from browsers. This could be a result of a potential web browser exploitation. - Legitimate browser install, update and recovery scripts"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "/bash" or FolderPath endswith "/curl" or FolderPath endswith "/dash" or FolderPath endswith "/ksh" or FolderPath endswith "/osascript" or FolderPath endswith "/perl" or FolderPath endswith "/php" or FolderPath endswith "/pwsh" or FolderPath endswith "/python" or FolderPath endswith "/sh" or FolderPath endswith "/tcsh" or FolderPath endswith "/wget" or FolderPath endswith "/zsh") and (InitiatingProcessFolderPath contains "com.apple.WebKit.WebContent" or InitiatingProcessFolderPath contains "firefox" or InitiatingProcessFolderPath contains "Google Chrome Helper" or InitiatingProcessFolderPath contains "Google Chrome" or InitiatingProcessFolderPath contains "Microsoft Edge" or InitiatingProcessFolderPath contains "Opera" or InitiatingProcessFolderPath contains "Safari" or InitiatingProcessFolderPath contains "Tor Browser")) and (not(((((ProcessCommandLine contains "/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/" and ProcessCommandLine contains "/Resources/install.sh") or (ProcessCommandLine contains "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/" and ProcessCommandLine contains "/Resources/keystone_promote_preflight.sh") or (ProcessCommandLine contains "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/" and ProcessCommandLine contains "/Resources/keystone_promote_postflight.sh")) and (InitiatingProcessFolderPath contains "Google Chrome Helper" or InitiatingProcessFolderPath contains "Google Chrome")) or ((ProcessCommandLine contains "/Users/" and ProcessCommandLine contains "/Library/Application Support/Google/Chrome/recovery/" and ProcessCommandLine contains "/ChromeRecovery") and (InitiatingProcessFolderPath contains "Google Chrome Helper" or InitiatingProcessFolderPath contains "Google Chrome")) or ProcessCommandLine contains "--defaults-torrc" or ProcessCommandLine =~ "*/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate*" or ((ProcessCommandLine contains "IOPlatformExpertDevice" or ProcessCommandLine contains "hw.model") and InitiatingProcessFolderPath contains "Microsoft Edge")))) and (not((ProcessCommandLine =~ "" or isnull(ProcessCommandLine))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Execution"]
  techniques                 = ["T1189", "T1203", "T1059"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}