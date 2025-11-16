resource "azurerm_sentinel_alert_rule_scheduled" "potential_apt_mustang_panda_activity_against_australian_gov" {
  name                       = "potential_apt_mustang_panda_activity_against_australian_gov"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential APT Mustang Panda Activity Against Australian Gov"
  description                = "Detects specific command line execution used by Mustang Panda in a targeted attack against the Australian government as reported by Lab52 - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "copy SolidPDFCreator.dll" and ProcessCommandLine contains "C:\\Users\\Public\\Libraries\\PhotoTvRHD\\SolidPDFCreator.dll") or (ProcessCommandLine contains "reg " and ProcessCommandLine contains "\\Windows\\CurrentVersion\\Run" and ProcessCommandLine contains "SolidPDF" and ProcessCommandLine contains "C:\\Users\\Public\\Libraries\\PhotoTvRHD\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
  }
}