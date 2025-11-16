resource "azurerm_sentinel_alert_rule_scheduled" "potential_dosfuscation_activity" {
  name                       = "potential_dosfuscation_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Dosfuscation Activity"
  description                = "Detects possible payload obfuscation via the commandline"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "^^" or ProcessCommandLine contains "^|^" or ProcessCommandLine contains ",;," or ProcessCommandLine contains ";;;;" or ProcessCommandLine contains ";; ;;" or ProcessCommandLine contains "(,(," or ProcessCommandLine contains "%COMSPEC:~" or ProcessCommandLine contains " c^m^d" or ProcessCommandLine contains "^c^m^d" or ProcessCommandLine contains " c^md" or ProcessCommandLine contains " cm^d" or ProcessCommandLine contains "^cm^d" or ProcessCommandLine contains " s^et " or ProcessCommandLine contains " s^e^t " or ProcessCommandLine contains " se^t "
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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