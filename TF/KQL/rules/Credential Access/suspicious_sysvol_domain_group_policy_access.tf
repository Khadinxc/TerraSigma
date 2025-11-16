resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_sysvol_domain_group_policy_access" {
  name                       = "suspicious_sysvol_domain_group_policy_access"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious SYSVOL Domain Group Policy Access"
  description                = "Detects Access to Domain Group Policies stored in SYSVOL - Administrative activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\SYSVOL\\" and ProcessCommandLine contains "\\policies\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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