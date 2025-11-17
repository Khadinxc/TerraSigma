resource "azurerm_sentinel_alert_rule_scheduled" "windows_shell_scripting_application_file_write_to_suspicious_folder" {
  name                       = "windows_shell_scripting_application_file_write_to_suspicious_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Shell/Scripting Application File Write to Suspicious Folder"
  description                = "Detects Windows shells and scripting applications that write files to suspicious folders"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\bash.exe" or InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\msbuild.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\sh.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe") and (FolderPath startswith "C:\\PerfLogs\\" or FolderPath startswith "C:\\Users\\Public\\")) or ((InitiatingProcessFolderPath endswith "\\certutil.exe" or InitiatingProcessFolderPath endswith "\\forfiles.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\schtasks.exe" or InitiatingProcessFolderPath endswith "\\scriptrunner.exe" or InitiatingProcessFolderPath endswith "\\wmic.exe") and (FolderPath contains "C:\\PerfLogs\\" or FolderPath contains "C:\\Users\\Public\\" or FolderPath contains "C:\\Windows\\Temp\\"))
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