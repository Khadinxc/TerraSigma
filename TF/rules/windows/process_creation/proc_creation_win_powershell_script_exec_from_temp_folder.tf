resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_script_exec_from_temp_folder" {
  name                       = "proc_creation_win_powershell_script_exec_from_temp_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Powershell Script Execution From Temp Folder"
  description                = <<DESC
    Detects a potentially suspicious powershell script executions from temporary folder

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_script_exec_from_temp_folder.yml

    False Positives:
    - Administrative scripts
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\Windows\\Temp" or ProcessCommandLine contains "\\Temporary Internet" or ProcessCommandLine contains "\\AppData\\Local\\Temp" or ProcessCommandLine contains "\\AppData\\Roaming\\Temp" or ProcessCommandLine contains "%TEMP%" or ProcessCommandLine contains "%TMP%" or ProcessCommandLine contains "%LocalAppData%\\Temp") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")) and (not((ProcessCommandLine contains "\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp\\Amazon\\EC2-Windows\\" or ((ProcessCommandLine contains "-NoProfile -ExecutionPolicy Bypass -Command" and ProcessCommandLine contains "AppData\\Local\\Temp\\" and ProcessCommandLine contains "Install-Chocolatey.ps1") and FolderPath endswith "\\powershell.exe" and (InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\Msiexec.exe", "C:\\Windows\\SysWOW64\\Msiexec.exe"))) or (ProcessCommandLine contains " >" or ProcessCommandLine contains "Out-File" or ProcessCommandLine contains "ConvertTo-Json") or ProcessCommandLine contains "-WindowStyle hidden -Verb runAs")))
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