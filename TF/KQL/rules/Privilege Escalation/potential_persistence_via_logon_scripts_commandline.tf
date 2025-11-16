resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_logon_scripts_commandline" {
  name                       = "potential_persistence_via_logon_scripts_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Logon Scripts - CommandLine"
  description                = "Detects the addition of a new LogonScript to the registry value \"UserInitMprLogonScript\" for potential persistence - Legitimate addition of Logon Scripts via the command line by administrators or third party tools"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "UserInitMprLogonScript"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1037"]
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