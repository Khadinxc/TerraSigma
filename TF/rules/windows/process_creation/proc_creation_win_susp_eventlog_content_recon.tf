resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_eventlog_content_recon" {
  name                       = "proc_creation_win_susp_eventlog_content_recon"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious EventLog Recon Activity Using Log Query Utilities"
  description                = <<DESC
    Detects execution of different log query utilities and commands to search and dump the content of specific event logs or look for specific event IDs. This technique is used by threat actors in order to extract sensitive information from events logs such as usernames, IP addresses, hostnames, etc.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_eventlog_content_recon.yml

    False Positives:
    - Legitimate usage of the utility by administrators to query the event log
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains "-InstanceId 462") or (ProcessCommandLine contains ".eventid -eq 462") or (ProcessCommandLine contains ".ID -eq 462") or (ProcessCommandLine contains "EventCode=" and ProcessCommandLine contains "462") or (ProcessCommandLine contains "EventIdentifier=" and ProcessCommandLine contains "462") or (ProcessCommandLine contains "System[EventID=462" and ProcessCommandLine contains "]") or ProcessCommandLine contains "-InstanceId 4778" or ProcessCommandLine contains ".eventid -eq 4778" or ProcessCommandLine contains ".ID -eq 4778" or (ProcessCommandLine contains "EventCode=" and ProcessCommandLine contains "4778") or (ProcessCommandLine contains "EventIdentifier=" and ProcessCommandLine contains "4778") or ProcessCommandLine contains "System[EventID=4778]" or ProcessCommandLine contains "-InstanceId 25" or ProcessCommandLine contains ".eventid -eq 25" or ProcessCommandLine contains ".ID -eq 25" or (ProcessCommandLine contains "EventCode=" and ProcessCommandLine contains "25") or (ProcessCommandLine contains "EventIdentifier=" and ProcessCommandLine contains "25") or ProcessCommandLine contains "System[EventID=25]" or ProcessCommandLine contains "-InstanceId 1149" or ProcessCommandLine contains ".eventid -eq 1149" or ProcessCommandLine contains ".ID -eq 1149" or (ProcessCommandLine contains "EventCode=" and ProcessCommandLine contains "1149") or (ProcessCommandLine contains "EventIdentifier=" and ProcessCommandLine contains "1149") or ProcessCommandLine contains "System[EventID=1149]" or ProcessCommandLine contains "-InstanceId 21" or ProcessCommandLine contains ".eventid -eq 21" or ProcessCommandLine contains ".ID -eq 21" or (ProcessCommandLine contains "EventCode=" and ProcessCommandLine contains "21") or (ProcessCommandLine contains "EventIdentifier=" and ProcessCommandLine contains "21") or ProcessCommandLine contains "System[EventID=21]" or ProcessCommandLine contains "-InstanceId 22" or ProcessCommandLine contains ".eventid -eq 22" or ProcessCommandLine contains ".ID -eq 22" or (ProcessCommandLine contains "EventCode=" and ProcessCommandLine contains "22") or (ProcessCommandLine contains "EventIdentifier=" and ProcessCommandLine contains "22") or ProcessCommandLine contains "System[EventID=22]") or (ProcessCommandLine contains "Microsoft-Windows-PowerShell" or ProcessCommandLine contains "Microsoft-Windows-Security-Auditing" or ProcessCommandLine contains "Microsoft-Windows-TerminalServices-LocalSessionManager" or ProcessCommandLine contains "Microsoft-Windows-TerminalServices-RemoteConnectionManager" or ProcessCommandLine contains "Microsoft-Windows-Windows Defender" or ProcessCommandLine contains "PowerShellCore" or ProcessCommandLine contains "Security" or ProcessCommandLine contains "Windows PowerShell")) and ((ProcessCommandLine contains "Select" and ProcessCommandLine contains "Win32_NTLogEvent") or ((ProcessCommandLine contains " qe " or ProcessCommandLine contains " query-events ") and (FolderPath endswith "\\wevtutil.exe" or ProcessVersionInfoOriginalFileName =~ "wevtutil.exe")) or (ProcessCommandLine contains " ntevent" and (FolderPath endswith "\\wmic.exe" or ProcessVersionInfoOriginalFileName =~ "wmic.exe")) or (ProcessCommandLine contains "Get-WinEvent " or ProcessCommandLine contains "get-eventlog "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "Discovery"]
  techniques                 = ["T1552", "T1087"]
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