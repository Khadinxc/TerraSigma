resource "azurerm_sentinel_alert_rule_scheduled" "potential_ransomware_activity_using_legalnotice_message" {
  name                       = "potential_ransomware_activity_using_legalnotice_message"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Ransomware Activity Using LegalNotice Message"
  description                = "Detect changes to the \"LegalNoticeCaption\" or \"LegalNoticeText\" registry values where the message set contains keywords often used in ransomware ransom messages"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "encrypted" or RegistryValueData contains "Unlock-Password" or RegistryValueData contains "paying") and (RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption" or RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1491"]
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