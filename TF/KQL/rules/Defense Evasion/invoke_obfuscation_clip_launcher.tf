resource "azurerm_sentinel_alert_rule_scheduled" "invoke_obfuscation_clip_launcher" {
  name                       = "invoke_obfuscation_clip_launcher"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Invoke-Obfuscation CLIP+ Launcher"
  description                = "Detects Obfuscated use of Clip.exe to execute PowerShell"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/c" or ProcessCommandLine contains "/r") and (ProcessCommandLine contains "cmd" and ProcessCommandLine contains "&&" and ProcessCommandLine contains "clipboard]::" and ProcessCommandLine contains "-f")
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