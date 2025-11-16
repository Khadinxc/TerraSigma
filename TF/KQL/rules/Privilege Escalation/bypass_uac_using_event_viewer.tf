resource "azurerm_sentinel_alert_rule_scheduled" "bypass_uac_using_event_viewer" {
  name                       = "bypass_uac_using_event_viewer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Bypass UAC Using Event Viewer"
  description                = "Bypasses User Account Control using Event Viewer and a relevant Windows Registry modification"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "_Classes\\mscfile\\shell\\open\\command\\(Default)" and (not(RegistryValueData startswith "%SystemRoot%\\system32\\mmc.exe \"%1\" %"))
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