resource "azurerm_sentinel_alert_rule_scheduled" "potential_privilege_escalation_via_service_permissions_weakness" {
  name                       = "potential_privilege_escalation_via_service_permissions_weakness"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Privilege Escalation via Service Permissions Weakness"
  description                = "Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\ImagePath" or ProcessCommandLine contains "\\FailureCommand" or ProcessCommandLine contains "\\ServiceDll") and (ProcessCommandLine contains "ControlSet" and ProcessCommandLine contains "services") and (ProcessIntegrityLevel in~ ("Medium", "S-1-16-8192"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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