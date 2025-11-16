resource "azurerm_sentinel_alert_rule_scheduled" "potential_boinc_software_execution_uc_berkeley_signature" {
  name                       = "potential_boinc_software_execution_uc_berkeley_signature"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential BOINC Software Execution (UC-Berkeley Signature)"
  description                = "Detects the use of software that is related to the University of California, Berkeley via metadata information. This indicates it may be related to BOINC software and can be used maliciously if unauthorized. - This software can be used for legitimate purposes when installed intentionally."
  severity                   = "Informational"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoFileDescription =~ "University of California, Berkeley"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1553"]
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