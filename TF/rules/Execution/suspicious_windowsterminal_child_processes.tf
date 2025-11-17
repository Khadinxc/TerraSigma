resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_windowsterminal_child_processes" {
  name                       = "suspicious_windowsterminal_child_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious WindowsTerminal Child Processes"
  description                = "Detects suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal (see references section) - Other legitimate \"Windows Terminal\" profiles"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((InitiatingProcessFolderPath endswith "\\WindowsTerminal.exe" or InitiatingProcessFolderPath endswith "\\wt.exe") and ((FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\csc.exe") or (FolderPath contains "C:\\Users\\Public\\" or FolderPath contains "\\Downloads\\" or FolderPath contains "\\Desktop\\" or FolderPath contains "\\AppData\\Local\\Temp\\" or FolderPath contains "\\Windows\\TEMP\\") or (ProcessCommandLine contains " iex " or ProcessCommandLine contains " icm" or ProcessCommandLine contains "Invoke-" or ProcessCommandLine contains "Import-Module " or ProcessCommandLine contains "ipmo " or ProcessCommandLine contains "DownloadString(" or ProcessCommandLine contains " /c " or ProcessCommandLine contains " /k " or ProcessCommandLine contains " /r "))) and (not(((ProcessCommandLine contains "Import-Module" and ProcessCommandLine contains "Microsoft.VisualStudio.DevShell.dll" and ProcessCommandLine contains "Enter-VsDevShell") or (ProcessCommandLine contains "\\AppData\\Local\\Packages\\Microsoft.WindowsTerminal_" and ProcessCommandLine contains "\\LocalState\\settings.json") or (ProcessCommandLine contains "C:\\Program Files\\Microsoft Visual Studio\\" and ProcessCommandLine contains "\\Common7\\Tools\\VsDevCmd.bat"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence"]
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