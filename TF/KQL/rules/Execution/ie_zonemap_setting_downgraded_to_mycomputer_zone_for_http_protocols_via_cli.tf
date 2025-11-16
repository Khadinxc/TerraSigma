resource "azurerm_sentinel_alert_rule_scheduled" "ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols_via_cli" {
  name                       = "ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols_via_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI"
  description                = "Detects changes to Internet Explorer's (IE / Windows Internet properties) ZoneMap configuration of the \"HTTP\" and \"HTTPS\" protocols to point to the \"My Computer\" zone. This allows downloaded files from the Internet to be granted the same level of trust as files stored locally."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProtocolDefaults" and ProcessCommandLine contains "http" and ProcessCommandLine contains " 0"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
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