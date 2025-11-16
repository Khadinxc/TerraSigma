resource "azurerm_sentinel_alert_rule_scheduled" "potential_sysinternals_procdump_evasion" {
  name                       = "potential_sysinternals_procdump_evasion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential SysInternals ProcDump Evasion"
  description                = "Detects uses of the SysInternals ProcDump utility in which ProcDump or its output get renamed, or a dump file is moved or copied to a different name"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "copy procdump" or ProcessCommandLine contains "move procdump") or ((ProcessCommandLine contains "2.dmp" or ProcessCommandLine contains "lsass" or ProcessCommandLine contains "out.dmp") and (ProcessCommandLine contains "copy " and ProcessCommandLine contains ".dmp ")) or (ProcessCommandLine contains "copy lsass.exe_" or ProcessCommandLine contains "move lsass.exe_")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1036", "T1003"]
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