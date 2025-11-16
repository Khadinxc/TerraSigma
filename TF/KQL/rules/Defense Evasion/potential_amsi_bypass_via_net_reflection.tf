resource "azurerm_sentinel_alert_rule_scheduled" "potential_amsi_bypass_via_net_reflection" {
  name                       = "potential_amsi_bypass_via_net_reflection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential AMSI Bypass Via .NET Reflection"
  description                = "Detects Request to \"amsiInitFailed\" that can be used to disable AMSI Scanning - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "System.Management.Automation.AmsiUtils" and ProcessCommandLine contains "amsiInitFailed") or (ProcessCommandLine contains "[Ref].Assembly.GetType" and ProcessCommandLine contains "SetValue($null,$true)" and ProcessCommandLine contains "NonPublic,Static")
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}