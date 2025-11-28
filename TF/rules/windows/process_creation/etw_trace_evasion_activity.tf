resource "azurerm_sentinel_alert_rule_scheduled" "etw_trace_evasion_activity" {
  name                       = "etw_trace_evasion_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ETW Trace Evasion Activity"
  description                = "Detects command line activity that tries to clear or disable any ETW trace log which could be a sign of logging evasion."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "cl" and ProcessCommandLine contains "/Trace") or (ProcessCommandLine contains "clear-log" and ProcessCommandLine contains "/Trace") or (ProcessCommandLine contains "sl" and ProcessCommandLine contains "/e:false") or (ProcessCommandLine contains "set-log" and ProcessCommandLine contains "/e:false") or (ProcessCommandLine contains "logman" and ProcessCommandLine contains "update" and ProcessCommandLine contains "trace" and ProcessCommandLine contains "--p" and ProcessCommandLine contains "-ets") or ProcessCommandLine contains "Remove-EtwTraceProvider" or (ProcessCommandLine contains "Set-EtwTraceProvider" and ProcessCommandLine contains "0x11")
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
}