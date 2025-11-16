resource "azurerm_sentinel_alert_rule_scheduled" "potential_apt_fin7_reconnaissance_powertrash_related_activity" {
  name                       = "potential_apt_fin7_reconnaissance_powertrash_related_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential APT FIN7 Reconnaissance/POWERTRASH Related Activity"
  description                = "Detects specific command line execution used by FIN7 as reported by WithSecureLabs for reconnaissance and POWERTRASH execution - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-noni -nop -exe bypass -f \\\\" and ProcessCommandLine contains "ADMIN$") or (ProcessCommandLine contains "-ex bypass -noprof -nolog -nonint -f" and ProcessCommandLine contains "C:\\Windows\\Temp\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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