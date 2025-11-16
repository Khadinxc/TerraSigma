resource "azurerm_sentinel_alert_rule_scheduled" "change_user_account_associated_with_the_fax_service" {
  name                       = "change_user_account_associated_with_the_fax_service"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Change User Account Associated with the FAX Service"
  description                = "Detect change of the user account associated with the FAX service to avoid the escalation problem."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey =~ "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001\\Services\\Fax\\ObjectName" and (not(RegistryValueData contains "NetworkService"))
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}