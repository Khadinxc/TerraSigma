resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_child_process_of_vscode" {
  name                       = "potentially_suspicious_child_process_of_vscode"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Child Process Of VsCode"
  description                = "Detects uncommon or suspicious child processes spawning from a VsCode \"code.exe\" process. This could indicate an attempt of persistence via VsCode tasks or terminal profiles."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\code.exe" and (((ProcessCommandLine contains "Invoke-Expressions" or ProcessCommandLine contains "IEX" or ProcessCommandLine contains "Invoke-Command" or ProcessCommandLine contains "ICM" or ProcessCommandLine contains "DownloadString" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "wscript" or ProcessCommandLine contains "cscript") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\cmd.exe")) or (FolderPath endswith "\\calc.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\wscript.exe") or (FolderPath contains ":\\Users\\Public\\" or FolderPath contains ":\\Windows\\Temp\\" or FolderPath contains ":\\Temp\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1218", "T1202"]
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