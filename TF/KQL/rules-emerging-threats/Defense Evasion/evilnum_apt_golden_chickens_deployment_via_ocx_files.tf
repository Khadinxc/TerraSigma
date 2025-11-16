resource "azurerm_sentinel_alert_rule_scheduled" "evilnum_apt_golden_chickens_deployment_via_ocx_files" {
  name                       = "evilnum_apt_golden_chickens_deployment_via_ocx_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "EvilNum APT Golden Chickens Deployment Via OCX Files"
  description                = "Detects Golden Chickens deployment method as used by Evilnum and described in ESET July 2020 report"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "regsvr32" and ProcessCommandLine contains "/s" and ProcessCommandLine contains "/i" and ProcessCommandLine contains "\\AppData\\Roaming\\" and ProcessCommandLine contains ".ocx"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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