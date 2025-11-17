resource "azurerm_sentinel_alert_rule_scheduled" "use_short_name_path_in_command_line" {
  name                       = "use_short_name_path_in_command_line"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Use Short Name Path in Command Line"
  description                = "Detects the use of short name paths (8.3 format) in command lines, which can be used to obfuscate paths or access restricted locations. Windows creates short 8.3 filenames (like PROGRA~1) for compatibility with MS-DOS-based or 16-bit Windows programs. When investigating, examine: - Commands using short paths to access sensitive directories or files - Web servers on Windows (especially Apache) where short filenames could bypass security controls - Correlation with other suspicious behaviors - baseline of short name usage in your environment and look for deviations - Applications could use this notation occasionally which might generate some false positives. In that case investigate the parent and child process."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "~1\\" or ProcessCommandLine contains "~2\\") and (not(((InitiatingProcessFolderPath endswith "\\csc.exe" and InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework64\\v") or ((FolderPath contains "\\AppData\\" and FolderPath contains "\\Temp\\") or ProcessCommandLine contains "\\AppData\\Local\\Temp\\") or (InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\Dism.exe", "C:\\Windows\\System32\\cleanmgr.exe")) or (InitiatingProcessFolderPath endswith "\\winget.exe" or InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\WinGet\\")))) and (not(((InitiatingProcessFolderPath endswith "\\aurora-agent-64.exe" or InitiatingProcessFolderPath endswith "\\aurora-agent.exe") or InitiatingProcessFolderPath =~ "C:\\Program Files\\GPSoftware\\Directory Opus\\dopus.exe" or InitiatingProcessFolderPath endswith "\\Everything\\Everything.exe" or (ProcessCommandLine contains "C:\\Program Files\\Git\\post-install.bat" or ProcessCommandLine contains "C:\\Program Files\\Git\\cmd\\scalar.exe") or InitiatingProcessFolderPath endswith "\\thor\\thor64.exe" or InitiatingProcessFolderPath endswith "\\veeam.backup.shell.exe" or (InitiatingProcessFolderPath endswith "\\WebEx\\webexhost.exe" or ProcessCommandLine contains "\\appdata\\local\\webex\\webex64\\meetings\\wbxreport.exe"))))
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}