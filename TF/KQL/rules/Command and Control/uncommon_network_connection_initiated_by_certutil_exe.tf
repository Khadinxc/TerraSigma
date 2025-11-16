resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_network_connection_initiated_by_certutil_exe" {
  name                       = "uncommon_network_connection_initiated_by_certutil_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Network Connection Initiated By Certutil.EXE"
  description                = "Detects a network connection initiated by the certutil.exe utility. Attackers can abuse the utility in order to download malware or additional payloads."
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemotePort in~ ("80", "135", "443", "445")) and InitiatingProcessFolderPath endswith "\\certutil.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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