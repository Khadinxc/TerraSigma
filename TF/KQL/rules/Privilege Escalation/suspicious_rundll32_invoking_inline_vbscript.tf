resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_rundll32_invoking_inline_vbscript" {
  name                       = "suspicious_rundll32_invoking_inline_vbscript"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Rundll32 Invoking Inline VBScript"
  description                = "Detects suspicious process related to rundll32 based on command line that invokes inline VBScript as seen being used by UNC2452"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "rundll32.exe" and ProcessCommandLine contains "Execute" and ProcessCommandLine contains "RegRead" and ProcessCommandLine contains "window.close"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
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