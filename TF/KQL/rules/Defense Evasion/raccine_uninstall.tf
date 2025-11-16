resource "azurerm_sentinel_alert_rule_scheduled" "raccine_uninstall" {
  name                       = "raccine_uninstall"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Raccine Uninstall"
  description                = "Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool. - Legitimate deinstallation by administrative staff"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "taskkill " and ProcessCommandLine contains "RaccineSettings.exe") or (ProcessCommandLine contains "reg.exe" and ProcessCommandLine contains "delete" and ProcessCommandLine contains "Raccine Tray") or (ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "/DELETE" and ProcessCommandLine contains "Raccine Rules Updater")
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