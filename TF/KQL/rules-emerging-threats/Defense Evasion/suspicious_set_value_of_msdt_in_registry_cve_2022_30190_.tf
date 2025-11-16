resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_set_value_of_msdt_in_registry_cve_2022_30190" {
  name                       = "suspicious_set_value_of_msdt_in_registry_cve_2022_30190"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Set Value of MSDT in Registry (CVE-2022-30190)"
  description                = "Detects set value ms-msdt MSProtocol URI scheme in Registry that could be an attempt to exploit CVE-2022-30190."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey =~ "HKEY_LOCAL_MACHINE\\CLASSES\\ms-msdt*"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1221"]
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