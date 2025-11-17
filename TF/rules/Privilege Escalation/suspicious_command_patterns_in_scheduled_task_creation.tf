resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_command_patterns_in_scheduled_task_creation" {
  name                       = "suspicious_command_patterns_in_scheduled_task_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Command Patterns In Scheduled Task Creation"
  description                = "Detects scheduled task creation using \"schtasks\" that contain potentially suspicious or uncommon commands - Software installers that run from temporary folders and also install scheduled tasks are expected to generate some false positives"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/Create " and FolderPath endswith "\\schtasks.exe") and (((ProcessCommandLine contains "/sc minute " or ProcessCommandLine contains "/ru system ") and (ProcessCommandLine contains "cmd /c" or ProcessCommandLine contains "cmd /k" or ProcessCommandLine contains "cmd /r" or ProcessCommandLine contains "cmd.exe /c " or ProcessCommandLine contains "cmd.exe /k " or ProcessCommandLine contains "cmd.exe /r ")) or (ProcessCommandLine contains " -decode " or ProcessCommandLine contains " -enc " or ProcessCommandLine contains " -w hidden " or ProcessCommandLine contains " bypass " or ProcessCommandLine contains " IEX" or ProcessCommandLine contains ".DownloadData" or ProcessCommandLine contains ".DownloadFile" or ProcessCommandLine contains ".DownloadString" or ProcessCommandLine contains "/c start /min " or ProcessCommandLine contains "FromBase64String" or ProcessCommandLine contains "mshta http" or ProcessCommandLine contains "mshta.exe http") or ((ProcessCommandLine contains ":\\ProgramData\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Tmp\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\AppData\\" or ProcessCommandLine contains "%AppData%" or ProcessCommandLine contains "%Temp%" or ProcessCommandLine contains "%tmp%") and (ProcessCommandLine contains "cscript" or ProcessCommandLine contains "curl" or ProcessCommandLine contains "wscript")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "Execution"]
  techniques                 = ["T1053"]
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