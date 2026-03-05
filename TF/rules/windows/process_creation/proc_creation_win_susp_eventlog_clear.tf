resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_eventlog_clear" {
  name                       = "proc_creation_win_susp_eventlog_clear"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Eventlog Clearing or Configuration Change Activity"
  description                = <<DESC
    Detects the clearing or configuration tampering of EventLog using utilities such as "wevtutil", "powershell" and "wmic". This technique were seen used by threat actors and ransomware strains in order to evade defenses.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml

    False Positives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment
    - Maintenance activity
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "clear-log " or ProcessCommandLine contains " cl " or ProcessCommandLine contains "set-log " or ProcessCommandLine contains " sl " or ProcessCommandLine contains "lfn:") and (FolderPath endswith "\\wevtutil.exe" or ProcessVersionInfoOriginalFileName =~ "wevtutil.exe")) or (((ProcessCommandLine contains "Clear-EventLog " or ProcessCommandLine contains "Remove-EventLog " or ProcessCommandLine contains "Limit-EventLog " or ProcessCommandLine contains "Clear-WinEvent ") or (ProcessCommandLine contains "Eventing.Reader.EventLogSession" and ProcessCommandLine contains "ClearLog") or (ProcessCommandLine contains "Diagnostics.EventLog" and ProcessCommandLine contains "Clear")) and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe")) or ((ProcessCommandLine contains "ClearEventLog" and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wmic.exe")) and (not((ProcessCommandLine contains " sl " and (InitiatingProcessFolderPath in~ ("C:\\Windows\\SysWOW64\\msiexec.exe", "C:\\Windows\\System32\\msiexec.exe"))))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070", "T1562"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}