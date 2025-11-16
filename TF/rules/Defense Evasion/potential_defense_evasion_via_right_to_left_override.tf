resource "azurerm_sentinel_alert_rule_scheduled" "potential_defense_evasion_via_right_to_left_override" {
  name                       = "potential_defense_evasion_via_right_to_left_override"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Defense Evasion Via Right-to-Left Override"
  description                = "Detects the presence of the \"u202+E\" character, which causes a terminal, browser, or operating system to render text in a right-to-left sequence. This is used as an obfuscation and masquerading techniques. - Commandlines that contains scriptures such as arabic or hebrew might make use of this character"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\u202e" or ProcessCommandLine contains "[U+202E]"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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