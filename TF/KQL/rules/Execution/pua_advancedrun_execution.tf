resource "azurerm_sentinel_alert_rule_scheduled" "pua_advancedrun_execution" {
  name                       = "pua_advancedrun_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - AdvancedRun Execution"
  description                = "Detects the execution of AdvancedRun utility"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName =~ "AdvancedRun.exe" or (ProcessCommandLine contains " /EXEFilename " and ProcessCommandLine contains " /Run") or (ProcessCommandLine contains " /WindowState 0" and ProcessCommandLine contains " /RunAs " and ProcessCommandLine contains " /CommandLine ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1564", "T1134", "T1059"]
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