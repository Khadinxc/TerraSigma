resource "azurerm_sentinel_alert_rule_scheduled" "potential_pikabot_c2_activity" {
  name                       = "potential_pikabot_c2_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Pikabot C2 Activity"
  description                = "Detects the execution of rundll32 that leads to an external network connection. The malware Pikabot has been seen to use this technique to initiate C2-communication through hard-coded Windows binaries. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where (InitiatingProcessFolderPath endswith "\\SearchFilterHost.exe" or InitiatingProcessFolderPath endswith "\\SearchProtocolHost.exe" or InitiatingProcessFolderPath endswith "\\sndvol.exe" or InitiatingProcessFolderPath endswith "\\wermgr.exe" or InitiatingProcessFolderPath endswith "\\wwahost.exe") and InitiatingProcessParentFileName =~ "rundll32.exe" and Protocol =~ "tcp"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1573"]
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
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }
}