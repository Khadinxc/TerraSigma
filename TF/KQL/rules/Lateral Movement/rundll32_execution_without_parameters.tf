resource "azurerm_sentinel_alert_rule_scheduled" "rundll32_execution_without_parameters" {
  name                       = "rundll32_execution_without_parameters"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Rundll32 Execution Without Parameters"
  description                = "Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine in~ ("rundll32.exe", "rundll32")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement", "Execution"]
  techniques                 = ["T1021", "T1570", "T1569"]
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