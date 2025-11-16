resource "azurerm_sentinel_alert_rule_scheduled" "mshtml_dll_runhtmlapplication_suspicious_usage" {
  name                       = "mshtml_dll_runhtmlapplication_suspicious_usage"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Mshtml.DLL RunHTMLApplication Suspicious Usage"
  description                = "Detects execution of commands that leverage the \"mshtml.dll\" RunHTMLApplication export to run arbitrary code via different protocol handlers (vbscript, javascript, file, http...) - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "#135" or ProcessCommandLine contains "RunHTMLApplication") and (ProcessCommandLine contains "\\..\\" and ProcessCommandLine contains "mshtml")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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