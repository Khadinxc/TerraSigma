resource "azurerm_sentinel_alert_rule_scheduled" "potential_homoglyph_attack_using_lookalike_characters" {
  name                       = "potential_homoglyph_attack_using_lookalike_characters"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Homoglyph Attack Using Lookalike Characters"
  description                = "Detects the presence of unicode characters which are homoglyphs, or identical in appearance, to ASCII letter characters. This is used as an obfuscation and masquerading techniques. Only \"perfect\" homoglyphs are included; these are characters that are indistinguishable from ASCII characters and thus may make excellent candidates for homoglyph attack characters. - Commandlines with legitimate Cyrillic text; will likely require tuning (or not be usable) in countries where these alphabets are in use."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "а" or ProcessCommandLine contains "е" or ProcessCommandLine contains "о" or ProcessCommandLine contains "р" or ProcessCommandLine contains "с" or ProcessCommandLine contains "х" or ProcessCommandLine contains "ѕ" or ProcessCommandLine contains "і" or ProcessCommandLine contains "ӏ" or ProcessCommandLine contains "ј" or ProcessCommandLine contains "һ" or ProcessCommandLine contains "ԁ" or ProcessCommandLine contains "ԛ" or ProcessCommandLine contains "ԝ" or ProcessCommandLine contains "ο") or (ProcessCommandLine contains "А" or ProcessCommandLine contains "В" or ProcessCommandLine contains "Е" or ProcessCommandLine contains "К" or ProcessCommandLine contains "М" or ProcessCommandLine contains "Н" or ProcessCommandLine contains "О" or ProcessCommandLine contains "Р" or ProcessCommandLine contains "С" or ProcessCommandLine contains "Т" or ProcessCommandLine contains "Х" or ProcessCommandLine contains "Ѕ" or ProcessCommandLine contains "І" or ProcessCommandLine contains "Ј" or ProcessCommandLine contains "Ү" or ProcessCommandLine contains "Ӏ" or ProcessCommandLine contains "Ԍ" or ProcessCommandLine contains "Ԛ" or ProcessCommandLine contains "Ԝ" or ProcessCommandLine contains "Α" or ProcessCommandLine contains "Β" or ProcessCommandLine contains "Ε" or ProcessCommandLine contains "Ζ" or ProcessCommandLine contains "Η" or ProcessCommandLine contains "Ι" or ProcessCommandLine contains "Κ" or ProcessCommandLine contains "Μ" or ProcessCommandLine contains "Ν" or ProcessCommandLine contains "Ο" or ProcessCommandLine contains "Ρ" or ProcessCommandLine contains "Τ" or ProcessCommandLine contains "Υ" or ProcessCommandLine contains "Χ")
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