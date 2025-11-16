resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_attempt_via_existing_service_tampering" {
  name                       = "potential_persistence_attempt_via_existing_service_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Attempt Via Existing Service Tampering"
  description                = "Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "sc " and ProcessCommandLine contains "config " and ProcessCommandLine contains "binpath=") or (ProcessCommandLine contains "sc " and ProcessCommandLine contains "failure" and ProcessCommandLine contains "command=")) or ((ProcessCommandLine contains ".sh" or ProcessCommandLine contains ".exe" or ProcessCommandLine contains ".dll" or ProcessCommandLine contains ".bin$" or ProcessCommandLine contains ".bat" or ProcessCommandLine contains ".cmd" or ProcessCommandLine contains ".js" or ProcessCommandLine contains ".msh$" or ProcessCommandLine contains ".reg$" or ProcessCommandLine contains ".scr" or ProcessCommandLine contains ".ps" or ProcessCommandLine contains ".vb" or ProcessCommandLine contains ".jar" or ProcessCommandLine contains ".pl") and ((ProcessCommandLine contains "reg " and ProcessCommandLine contains "add " and ProcessCommandLine contains "FailureCommand") or (ProcessCommandLine contains "reg " and ProcessCommandLine contains "add " and ProcessCommandLine contains "ImagePath")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion", "Persistence"]
  techniques                 = ["T1543", "T1574"]
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