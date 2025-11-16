resource "azurerm_sentinel_alert_rule_scheduled" "macro_enabled_in_a_potentially_suspicious_document" {
  name                       = "macro_enabled_in_a_potentially_suspicious_document"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Macro Enabled In A Potentially Suspicious Document"
  description                = "Detects registry changes to Office trust records where the path is located in a potentially suspicious location - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "/AppData/Local/Microsoft/Windows/INetCache/" or RegistryKey contains "/AppData/Local/Temp/" or RegistryKey contains "/PerfLogs/" or RegistryKey contains "C:/Users/Public/" or RegistryKey contains "file:///D:/" or RegistryKey contains "file:///E:/") and RegistryKey contains "\\Security\\Trusted Documents\\TrustRecords"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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