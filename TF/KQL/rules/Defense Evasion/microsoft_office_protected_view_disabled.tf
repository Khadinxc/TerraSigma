resource "azurerm_sentinel_alert_rule_scheduled" "microsoft_office_protected_view_disabled" {
  name                       = "microsoft_office_protected_view_disabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Microsoft Office Protected View Disabled"
  description                = "Detects changes to Microsoft Office protected view registry keys with which the attacker disables this feature. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\SOFTWARE\\Microsoft\\Office*" and RegistryKey endswith "\\Security\\ProtectedView*") and ((RegistryValueData =~ "DWORD (0x00000000)" and (RegistryKey endswith "\\enabledatabasefileprotectedview" or RegistryKey endswith "\\enableforeigntextfileprotectedview")) or (RegistryValueData =~ "DWORD (0x00000001)" and (RegistryKey endswith "\\DisableAttachementsInPV" or RegistryKey endswith "\\DisableInternetFilesInPV" or RegistryKey endswith "\\DisableIntranetCheck" or RegistryKey endswith "\\DisableUnsafeLocationsInPV")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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