resource "azurerm_sentinel_alert_rule_scheduled" "turla_group_lateral_movement" {
  name                       = "turla_group_lateral_movement"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Turla Group Lateral Movement"
  description                = "Detects automated lateral movement by Turla group"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine startswith "net use \\\\%DomainController%\\C$ \"P@ssw0rd\" " or (ProcessCommandLine contains "dir c:\\" and ProcessCommandLine contains ".doc" and ProcessCommandLine contains " /s") or (ProcessCommandLine contains "dir %TEMP%\\" and ProcessCommandLine contains ".exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement", "Discovery"]
  techniques                 = ["T1059", "T1021", "T1083", "T1135"]
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