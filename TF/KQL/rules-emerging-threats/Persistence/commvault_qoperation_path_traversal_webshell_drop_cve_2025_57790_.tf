resource "azurerm_sentinel_alert_rule_scheduled" "commvault_qoperation_path_traversal_webshell_drop_cve_2025_57790" {
  name                       = "commvault_qoperation_path_traversal_webshell_drop_cve_2025_57790"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Commvault QOperation Path Traversal Webshell Drop (CVE-2025-57790)"
  description                = "Detects the use of qoperation.exe with the -file argument to write a JSP file to the webroot, indicating a webshell drop. This is a post-authentication step corresponding to CVE-2025-57790."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "qoperation" and ProcessCommandLine contains "exec" and ProcessCommandLine contains " -af " and ProcessCommandLine contains ".xml " and ProcessCommandLine contains "\\Apache\\webapps\\ROOT\\" and ProcessCommandLine contains ".jsp"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1505"]
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