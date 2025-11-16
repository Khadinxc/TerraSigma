resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_wmiexec_default_powershell_command" {
  name                       = "hacktool_wmiexec_default_powershell_command"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Wmiexec Default Powershell Command"
  description                = "Detects the execution of PowerShell with a specific flag sequence that is used by the Wmiexec script - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "-NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "LateralMovement"]
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