resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_printerports_creation_cve_2020_1048" {
  name                       = "suspicious_printerports_creation_cve_2020_1048"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PrinterPorts Creation (CVE-2020-1048)"
  description                = "Detects new commands that add new printer port which point to suspicious file - New printer port install on host"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Add-PrinterPort -Name" and (ProcessCommandLine contains ".exe" or ProcessCommandLine contains ".dll" or ProcessCommandLine contains ".bat")) or ProcessCommandLine contains "Generic / Text Only"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Execution"]
  techniques                 = ["T1059"]
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