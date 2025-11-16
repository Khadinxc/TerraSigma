resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_vbscript_un2452_pattern" {
  name                       = "suspicious_vbscript_un2452_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious VBScript UN2452 Pattern"
  description                = "Detects suspicious inline VBScript keywords as used by UNC2452"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Execute" and ProcessCommandLine contains "CreateObject" and ProcessCommandLine contains "RegRead" and ProcessCommandLine contains "window.close" and ProcessCommandLine contains "\\Microsoft\\Windows\\CurrentVersion") and (not(ProcessCommandLine contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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