resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_execution_pe_metadata" {
  name                       = "hacktool_execution_pe_metadata"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Hacktool Execution - PE Metadata"
  description                = "Detects the execution of different Windows based hacktools via PE metadata (company, product, etc.) even if the files have been renamed - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoCompanyName =~ "Cube0x0"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "ResourceDevelopment"]
  techniques                 = ["T1588", "T1003"]
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
}