resource "azurerm_sentinel_alert_rule_scheduled" "pua_mouse_lock_execution" {
  name                       = "pua_mouse_lock_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Mouse Lock Execution"
  description                = "In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool \"Mouse Lock\" as being used for both credential access and collection in security incidents. - Legitimate uses of Mouse Lock software"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoProductName contains "Mouse Lock" or ProcessVersionInfoCompanyName contains "Misc314" or ProcessCommandLine contains "Mouse Lock_"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "Collection"]
  techniques                 = ["T1056"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}