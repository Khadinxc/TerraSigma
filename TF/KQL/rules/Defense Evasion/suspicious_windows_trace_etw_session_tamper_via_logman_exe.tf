resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_windows_trace_etw_session_tamper_via_logman_exe" {
  name                       = "suspicious_windows_trace_etw_session_tamper_via_logman_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Windows Trace ETW Session Tamper Via Logman.EXE"
  description                = "Detects the execution of \"logman\" utility in order to disable or delete Windows trace sessions - Legitimate deactivation by administrative staff - Installer tools that disable services, e.g. before log collection agent installation"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "stop " or ProcessCommandLine contains "delete ") and (FolderPath endswith "\\logman.exe" or ProcessVersionInfoOriginalFileName =~ "Logman.exe") and (ProcessCommandLine contains "Circular Kernel Context Logger" or ProcessCommandLine contains "EventLog-" or ProcessCommandLine contains "SYSMON TRACE" or ProcessCommandLine contains "SysmonDnsEtwSession")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562", "T1070"]
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