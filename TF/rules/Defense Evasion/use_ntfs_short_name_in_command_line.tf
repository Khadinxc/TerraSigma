resource "azurerm_sentinel_alert_rule_scheduled" "use_ntfs_short_name_in_command_line" {
  name                       = "use_ntfs_short_name_in_command_line"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Use NTFS Short Name in Command Line"
  description                = "Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection - Applications could use this notation occasionally which might generate some false positives. In that case Investigate the parent and child process."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "~1.exe" or ProcessCommandLine contains "~1.bat" or ProcessCommandLine contains "~1.msi" or ProcessCommandLine contains "~1.vbe" or ProcessCommandLine contains "~1.vbs" or ProcessCommandLine contains "~1.dll" or ProcessCommandLine contains "~1.ps1" or ProcessCommandLine contains "~1.js" or ProcessCommandLine contains "~1.hta" or ProcessCommandLine contains "~2.exe" or ProcessCommandLine contains "~2.bat" or ProcessCommandLine contains "~2.msi" or ProcessCommandLine contains "~2.vbe" or ProcessCommandLine contains "~2.vbs" or ProcessCommandLine contains "~2.dll" or ProcessCommandLine contains "~2.ps1" or ProcessCommandLine contains "~2.js" or ProcessCommandLine contains "~2.hta") and (not(((InitiatingProcessFolderPath endswith "\\WebEx\\WebexHost.exe" or InitiatingProcessFolderPath endswith "\\thor\\thor64.exe") or ProcessCommandLine contains "C:\\xampp\\vcredist\\VCREDI~1.EXE")))
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