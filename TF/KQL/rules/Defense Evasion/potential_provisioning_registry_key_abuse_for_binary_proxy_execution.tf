resource "azurerm_sentinel_alert_rule_scheduled" "potential_provisioning_registry_key_abuse_for_binary_proxy_execution" {
  name                       = "potential_provisioning_registry_key_abuse_for_binary_proxy_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Provisioning Registry Key Abuse For Binary Proxy Execution"
  description                = "Detects potential abuse of the provisioning registry key for indirect command execution through \"Provlaunch.exe\"."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "SOFTWARE\\Microsoft\\Provisioning\\Commands\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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