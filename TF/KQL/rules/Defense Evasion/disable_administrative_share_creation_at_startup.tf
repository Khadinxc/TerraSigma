resource "azurerm_sentinel_alert_rule_scheduled" "disable_administrative_share_creation_at_startup" {
  name                       = "disable_administrative_share_creation_at_startup"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Administrative Share Creation at Startup"
  description                = "Administrative shares are hidden network shares created by Microsoft Windows NT operating systems that grant system administrators remote access to every disk volume on a network-connected system"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey endswith "\\Services\\LanmanServer\\Parameters*" and (RegistryKey endswith "\\AutoShareWks" or RegistryKey endswith "\\AutoShareServer")
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}