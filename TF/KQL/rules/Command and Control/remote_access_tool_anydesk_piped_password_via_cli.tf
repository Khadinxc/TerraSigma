resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_anydesk_piped_password_via_cli" {
  name                       = "remote_access_tool_anydesk_piped_password_via_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - AnyDesk Piped Password Via CLI"
  description                = "Detects piping the password to an anydesk instance via CMD and the '--set-password' flag. - Legitimate piping of the password to anydesk - Some FP could occur with similar tools that uses the same command line '--set-password'"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "/c " and ProcessCommandLine contains "echo " and ProcessCommandLine contains ".exe --set-password"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]
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