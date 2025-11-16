resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_desktopimgdownldr_command" {
  name                       = "suspicious_desktopimgdownldr_command"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Desktopimgdownldr Command"
  description                = "Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " /lockscreenurl:" and (not((ProcessCommandLine contains ".jpg" or ProcessCommandLine contains ".jpeg" or ProcessCommandLine contains ".png")))) or (ProcessCommandLine contains "reg delete" and ProcessCommandLine contains "\\PersonalizationCSP")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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