resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_child_process_of_bginfo_exe" {
  name                       = "suspicious_child_process_of_bginfo_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Child Process Of BgInfo.EXE"
  description                = "Detects suspicious child processes of \"BgInfo.exe\" which could be a sign of potential abuse of the binary to proxy execution via external VBScript"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\calc.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\notepad.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wscript.exe") or (FolderPath contains "\\AppData\\Local\\" or FolderPath contains "\\AppData\\Roaming\\" or FolderPath contains ":\\Users\\Public\\" or FolderPath contains ":\\Temp\\" or FolderPath contains ":\\Windows\\Temp\\" or FolderPath contains ":\\PerfLogs\\")) and (InitiatingProcessFolderPath endswith "\\bginfo.exe" or InitiatingProcessFolderPath endswith "\\bginfo64.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1218", "T1202"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}