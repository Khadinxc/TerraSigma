resource "azurerm_sentinel_alert_rule_scheduled" "eventlog_query_requests_by_builtin_utilities" {
  name                       = "eventlog_query_requests_by_builtin_utilities"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "EventLog Query Requests By Builtin Utilities"
  description                = "Detect attempts to query the contents of the event log using command line utilities. Attackers use this technique in order to look for sensitive information in the logs such as passwords, usernames, IPs, etc. - Legitimate log access by administrators or troubleshooting tools"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Select" and ProcessCommandLine contains "Win32_NTLogEvent") or ((ProcessCommandLine contains " qe " or ProcessCommandLine contains " query-events ") and (FolderPath endswith "\\wevtutil.exe" or ProcessVersionInfoOriginalFileName =~ "wevtutil.exe")) or (ProcessCommandLine contains " ntevent" and (FolderPath endswith "\\wmic.exe" or ProcessVersionInfoOriginalFileName =~ "wmic.exe")) or (ProcessCommandLine contains "Get-WinEvent " or ProcessCommandLine contains "get-eventlog ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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