resource "azurerm_sentinel_alert_rule_scheduled" "uninstall_crowdstrike_falcon_sensor" {
  name                       = "uninstall_crowdstrike_falcon_sensor"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uninstall Crowdstrike Falcon Sensor"
  description                = "Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon - Administrator might leverage the same command line for debugging or other purposes. However this action must be always investigated"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\WindowsSensor.exe" and ProcessCommandLine contains " /uninstall" and ProcessCommandLine contains " /quiet"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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