resource "azurerm_sentinel_alert_rule_scheduled" "invoke_obfuscation_var_launcher_obfuscation" {
  name                       = "invoke_obfuscation_var_launcher_obfuscation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION"
  description                = "Detects Obfuscated Powershell via VAR++ LAUNCHER"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "{0}" or ProcessCommandLine contains "{1}" or ProcessCommandLine contains "{2}" or ProcessCommandLine contains "{3}" or ProcessCommandLine contains "{4}" or ProcessCommandLine contains "{5}") and (ProcessCommandLine contains "&&set" and ProcessCommandLine contains "cmd" and ProcessCommandLine contains "/c" and ProcessCommandLine contains "-f")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1027", "T1059"]
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