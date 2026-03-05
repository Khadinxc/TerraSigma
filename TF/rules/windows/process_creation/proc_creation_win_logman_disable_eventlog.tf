resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_logman_disable_eventlog" {
  name                       = "proc_creation_win_logman_disable_eventlog"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Windows Trace ETW Session Tamper Via Logman.EXE"
  description                = <<DESC
    Detects the execution of "logman" utility in order to disable or delete Windows trace sessions

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_logman_disable_eventlog.yml

    False Positives:
    - Legitimate deactivation by administrative staff
    - Installer tools that disable services, e.g. before log collection agent installation
  DESC
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