resource "azurerm_sentinel_alert_rule_scheduled" "potential_commandline_obfuscation_using_unicode_characters" {
  name                       = "potential_commandline_obfuscation_using_unicode_characters"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential CommandLine Obfuscation Using Unicode Characters"
  description                = "Detects potential CommandLine obfuscation using unicode characters. Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "ˣ" or ProcessCommandLine contains "˪" or ProcessCommandLine contains "ˢ" or ProcessCommandLine contains "∕" or ProcessCommandLine contains "⁄" or ProcessCommandLine contains "―" or ProcessCommandLine contains "—" or ProcessCommandLine contains " " or ProcessCommandLine contains "¯" or ProcessCommandLine contains "®" or ProcessCommandLine contains "¶"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1027"]
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