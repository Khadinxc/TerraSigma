resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_wscript_cscript_mshta_dropper" {
  name                       = "proc_creation_win_wscript_cscript_mshta_dropper"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Dropper Script Execution Via WScript/CScript/MSHTA"
  description                = <<DESC
    Detects wscript/cscript/mshta executions of scripts located in user directories

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wscript_cscript_mshta_dropper.yml

    False Positives:
    - Some installers might generate a similar behavior. An initial baseline is required
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe") and (ProcessCommandLine contains ".hta" or ProcessCommandLine contains ".js" or ProcessCommandLine contains ".jse" or ProcessCommandLine contains ".vba" or ProcessCommandLine contains ".vbe" or ProcessCommandLine contains ".vbs" or ProcessCommandLine contains ".wsf" or ProcessCommandLine contains ".wsh") and (ProcessCommandLine contains ":\\Perflogs\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Tmp\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\AppData\\Roaming\\Temp\\" or ProcessCommandLine contains "\\Start Menu\\Programs\\Startup\\" or ProcessCommandLine contains "\\Temporary Internet" or ProcessCommandLine contains "\\Windows\\Temp" or ProcessCommandLine contains "%LocalAppData%\\Temp\\" or ProcessCommandLine contains "%TEMP%" or ProcessCommandLine contains "%TMP%")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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