resource "azurerm_sentinel_alert_rule_scheduled" "pua_advancedrun_suspicious_execution" {
  name                       = "pua_advancedrun_suspicious_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - AdvancedRun Suspicious Execution"
  description                = "Detects the execution of AdvancedRun utility in the context of the TrustedInstaller, SYSTEM, Local Service or Network Service accounts"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/EXEFilename" or ProcessCommandLine contains "/CommandLine") and ((ProcessCommandLine contains " /RunAs 8 " or ProcessCommandLine contains " /RunAs 4 " or ProcessCommandLine contains " /RunAs 10 " or ProcessCommandLine contains " /RunAs 11 ") or (ProcessCommandLine endswith "/RunAs 8" or ProcessCommandLine endswith "/RunAs 4" or ProcessCommandLine endswith "/RunAs 10" or ProcessCommandLine endswith "/RunAs 11"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1134"]
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
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
  }
}