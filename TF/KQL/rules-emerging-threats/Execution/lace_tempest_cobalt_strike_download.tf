resource "azurerm_sentinel_alert_rule_scheduled" "lace_tempest_cobalt_strike_download" {
  name                       = "lace_tempest_cobalt_strike_download"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Lace Tempest Cobalt Strike Download"
  description                = "Detects specific command line execution used by Lace Tempest to download Cobalt Strike as reported by SysAid Team - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "-nop -w hidden -c IEX ((new-object net.webclient).downloadstring(" and ProcessCommandLine contains "/a')"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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