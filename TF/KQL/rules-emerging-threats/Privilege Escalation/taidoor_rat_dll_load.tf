resource "azurerm_sentinel_alert_rule_scheduled" "taidoor_rat_dll_load" {
  name                       = "taidoor_rat_dll_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "TAIDOOR RAT DLL Load"
  description                = "Detects specific process characteristics of Chinese TAIDOOR RAT malware load"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "dll,MyStart" or ProcessCommandLine contains "dll MyStart") or (ProcessCommandLine endswith " MyStart" and ProcessCommandLine contains "rundll32.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion", "Execution"]
  techniques                 = ["T1055"]
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