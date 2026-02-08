resource "azurerm_sentinel_alert_rule_scheduled" "cmd_launched_with_hidden_start_flags_to_suspicious_targets" {
  name                       = "cmd_launched_with_hidden_start_flags_to_suspicious_targets"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cmd Launched with Hidden Start Flags to Suspicious Targets"
  description                = "Detects cmd.exe executing commands with the \"start\" utility using \"/b\" (no window) or \"/min\" (minimized) flags. To reduce false positives from standard background tasks, detection is restricted to scenarios where the target is a known script extension or located in suspicious temporary/public directories. This technique was observed in Chaos, DarkSide, and Emotet malware campaigns. - Legitimate administrative scripts running from temporary folders. - Niche software updaters utilizing hidden batch files in ProgramData."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "start " or ProcessCommandLine contains "start/b" or ProcessCommandLine contains "start/min") and (ProcessCommandLine contains "-b " or ProcessCommandLine contains "/b " or ProcessCommandLine contains "–b " or ProcessCommandLine contains "—b " or ProcessCommandLine contains "―b " or ProcessCommandLine contains "-b\"" or ProcessCommandLine contains "/b\"" or ProcessCommandLine contains "–b\"" or ProcessCommandLine contains "—b\"" or ProcessCommandLine contains "―b\"" or ProcessCommandLine contains "-min " or ProcessCommandLine contains "/min " or ProcessCommandLine contains "–min " or ProcessCommandLine contains "—min " or ProcessCommandLine contains "―min " or ProcessCommandLine contains "-min\"" or ProcessCommandLine contains "/min\"" or ProcessCommandLine contains "–min\"" or ProcessCommandLine contains "—min\"" or ProcessCommandLine contains "―min\"") and (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe")) and ((ProcessCommandLine contains ".bat" or ProcessCommandLine contains ".cmd" or ProcessCommandLine contains ".cpl" or ProcessCommandLine contains ".hta" or ProcessCommandLine contains ".js" or ProcessCommandLine contains ".ps1" or ProcessCommandLine contains ".scr" or ProcessCommandLine contains ".vbe" or ProcessCommandLine contains ".vbs") or (ProcessCommandLine contains " -nop " or ProcessCommandLine contains " -sta " or ProcessCommandLine contains ".downloadfile(" or ProcessCommandLine contains ".downloadstring(" or ProcessCommandLine contains "-noni " or ProcessCommandLine contains "-w hidden ") or (ProcessCommandLine contains ":\\Perflogs\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Users\\Default\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\AppData\\Roaming\\" or ProcessCommandLine contains "\\Contacts\\" or ProcessCommandLine contains "\\Documents\\" or ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Favorites\\" or ProcessCommandLine contains "\\Favourites\\" or ProcessCommandLine contains "\\inetpub\\" or ProcessCommandLine contains "\\Music\\" or ProcessCommandLine contains "\\Photos\\" or ProcessCommandLine contains "\\Temporary Internet\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\Videos\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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