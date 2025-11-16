resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_hydra_password_bruteforce_execution" {
  name                       = "hacktool_hydra_password_bruteforce_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Hydra Password Bruteforce Execution"
  description                = "Detects command line parameters used by Hydra password guessing hack tool - Software that uses the caret encased keywords PASS and USER in its command line"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "^USER^" or ProcessCommandLine contains "^PASS^") and (ProcessCommandLine contains "-u " and ProcessCommandLine contains "-p ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110"]
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