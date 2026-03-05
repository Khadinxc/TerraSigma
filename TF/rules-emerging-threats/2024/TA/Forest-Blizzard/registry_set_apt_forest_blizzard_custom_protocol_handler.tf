resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_apt_forest_blizzard_custom_protocol_handler" {
  name                       = "registry_set_apt_forest_blizzard_custom_protocol_handler"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Forest Blizzard APT - Custom Protocol Handler Creation"
  description                = <<DESC
    Detects the setting of a custom protocol handler with the name "rogue". Seen being created by Forest Blizzard APT as reported by MSFT.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2024/TA/Forest-Blizzard/registry_set_apt_forest_blizzard_custom_protocol_handler.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "{026CC6D7-34B2-33D5-B551-CA31EB6CE345}" and RegistryKey contains "\\PROTOCOLS\\Handler\\rogue\\CLSID"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}