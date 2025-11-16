resource "azurerm_sentinel_alert_rule_scheduled" "maxmpxct_registry_value_changed" {
  name                       = "maxmpxct_registry_value_changed"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "MaxMpxCt Registry Value Changed"
  description                = "Detects changes to the \"MaxMpxCt\" registry value. MaxMpxCt specifies the maximum outstanding network requests for the server per client, which is used when negotiating a Server Message Block (SMB) connection with a client. Note if the value is set beyond 125 older Windows 9x clients will fail to negotiate. Ransomware threat actors and operators (specifically BlackCat) were seen increasing this value in order to handle a higher volume of traffic."
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Services\\LanmanServer\\Parameters\\MaxMpxCt"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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
  }
}