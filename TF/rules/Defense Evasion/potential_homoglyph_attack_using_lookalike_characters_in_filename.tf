resource "azurerm_sentinel_alert_rule_scheduled" "potential_homoglyph_attack_using_lookalike_characters_in_filename" {
  name                       = "potential_homoglyph_attack_using_lookalike_characters_in_filename"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Homoglyph Attack Using Lookalike Characters in Filename"
  description                = "Detects the presence of unicode characters which are homoglyphs, or identical in appearance, to ASCII letter characters. This is used as an obfuscation and masquerading techniques. Only \"perfect\" homoglyphs are included; these are characters that are indistinguishable from ASCII characters and thus may make excellent candidates for homoglyph attack characters. - File names with legitimate Cyrillic text. Will likely require tuning (or not be usable) in countries where these alphabets are in use."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "а" or FolderPath contains "е" or FolderPath contains "о" or FolderPath contains "р" or FolderPath contains "с" or FolderPath contains "х" or FolderPath contains "ѕ" or FolderPath contains "і" or FolderPath contains "ӏ" or FolderPath contains "ј" or FolderPath contains "һ" or FolderPath contains "ԁ" or FolderPath contains "ԛ" or FolderPath contains "ԝ" or FolderPath contains "ο") or (FolderPath contains "А" or FolderPath contains "В" or FolderPath contains "Е" or FolderPath contains "К" or FolderPath contains "М" or FolderPath contains "Н" or FolderPath contains "О" or FolderPath contains "Р" or FolderPath contains "С" or FolderPath contains "Т" or FolderPath contains "Х" or FolderPath contains "Ѕ" or FolderPath contains "І" or FolderPath contains "Ј" or FolderPath contains "Ү" or FolderPath contains "Ӏ" or FolderPath contains "Ԍ" or FolderPath contains "Ԛ" or FolderPath contains "Ԝ" or FolderPath contains "Α" or FolderPath contains "Β" or FolderPath contains "Ε" or FolderPath contains "Ζ" or FolderPath contains "Η" or FolderPath contains "Ι" or FolderPath contains "Κ" or FolderPath contains "Μ" or FolderPath contains "Ν" or FolderPath contains "Ο" or FolderPath contains "Ρ" or FolderPath contains "Τ" or FolderPath contains "Υ" or FolderPath contains "Χ")
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}