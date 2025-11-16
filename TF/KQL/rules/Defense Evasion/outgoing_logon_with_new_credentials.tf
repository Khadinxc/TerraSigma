resource "azurerm_sentinel_alert_rule_scheduled" "outgoing_logon_with_new_credentials" {
  name                       = "outgoing_logon_with_new_credentials"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Outgoing Logon with New Credentials"
  description                = "Detects logon events that specify new credentials - Legitimate remote administration activity"
  severity                   = "Low"
  query                      = <<QUERY
DeviceLogonEvents
| where LogonType == 9
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "LateralMovement"]
  techniques                 = ["T1550"]
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