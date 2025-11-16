resource "azurerm_sentinel_alert_rule_scheduled" "potential_credential_dumping_attempt_using_new_networkprovider_cli" {
  name                       = "potential_credential_dumping_attempt_using_new_networkprovider_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Credential Dumping Attempt Using New NetworkProvider - CLI"
  description                = "Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it - Other legitimate network providers used and not filtred in this rule"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\System\\CurrentControlSet\\Services\\" and ProcessCommandLine contains "\\NetworkProvider"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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