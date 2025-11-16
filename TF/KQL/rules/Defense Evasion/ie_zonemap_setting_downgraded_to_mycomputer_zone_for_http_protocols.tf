resource "azurerm_sentinel_alert_rule_scheduled" "ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols" {
  name                       = "ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols"
  description                = "Detects changes to Internet Explorer's (IE / Windows Internet properties) ZoneMap configuration of the \"HTTP\" and \"HTTPS\" protocols to point to the \"My Computer\" zone. This allows downloaded files from the Internet to be granted the same level of trust as files stored locally."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData contains "DWORD (0x00000000)" and RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProtocolDefaults" and (RegistryKey endswith "\\http" or RegistryKey endswith "\\https")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}