resource "azurerm_sentinel_alert_rule_scheduled" "silenttrinity_stager_msbuild_activity" {
  name                       = "silenttrinity_stager_msbuild_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Silenttrinity Stager Msbuild Activity"
  description                = "Detects a possible remote connections to Silenttrinity c2"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\msbuild.exe" and (RemotePort in~ ("80", "443"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1127"]
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