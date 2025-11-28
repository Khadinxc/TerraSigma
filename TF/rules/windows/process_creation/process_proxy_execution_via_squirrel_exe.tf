resource "azurerm_sentinel_alert_rule_scheduled" "process_proxy_execution_via_squirrel_exe" {
  name                       = "process_proxy_execution_via_squirrel_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Proxy Execution Via Squirrel.EXE"
  description                = "Detects the usage of the \"Squirrel.exe\" binary to execute arbitrary processes. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.) - Expected FP with some Electron based applications such as (1Clipboard, Beaker Browser, Caret, Discord, GitHub Desktop, etc.)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "--processStart" or ProcessCommandLine contains "--processStartAndWait" or ProcessCommandLine contains "--createShortcut") and (FolderPath endswith "\\squirrel.exe" or FolderPath endswith "\\update.exe")) and (not((((ProcessCommandLine contains "--createShortcut" or ProcessCommandLine contains "--processStart") and (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\AppData\\Local\\Discord\\Update.exe" and ProcessCommandLine contains "Discord.exe")) or ((ProcessCommandLine contains "--createShortcut" or ProcessCommandLine contains "--processStartAndWait") and (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\AppData\\Local\\GitHubDesktop\\Update.exe" and ProcessCommandLine contains "GitHubDesktop.exe")) or ((ProcessCommandLine contains "--processStart" or ProcessCommandLine contains "--createShortcut") and (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\AppData\\Local\\Microsoft\\Teams\\Update.exe" and ProcessCommandLine contains "Teams.exe")) or ((ProcessCommandLine contains "--processStart" or ProcessCommandLine contains "--createShortcut") and (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\AppData\\Local\\yammerdesktop\\Update.exe" and ProcessCommandLine contains "Yammer.exe")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1218"]
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