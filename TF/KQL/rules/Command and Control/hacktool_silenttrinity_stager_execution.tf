resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_silenttrinity_stager_execution" {
  name                       = "hacktool_silenttrinity_stager_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SILENTTRINITY Stager Execution"
  description                = "Detects SILENTTRINITY stager use via PE metadata - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoFileDescription contains "st2stager"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1071"]
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
}