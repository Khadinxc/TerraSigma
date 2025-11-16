resource "azurerm_sentinel_alert_rule_scheduled" "com_hijack_via_sdclt" {
  name                       = "com_hijack_via_sdclt"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "COM Hijack via Sdclt"
  description                = "Detects changes to 'HKCU\\Software\\Classes\\Folder\\shell\\open\\command\\DelegateExecute'"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Software\\Classes\\Folder\\shell\\open\\command\\DelegateExecute"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1546", "T1548"]
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