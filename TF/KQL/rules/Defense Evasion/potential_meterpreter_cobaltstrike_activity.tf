resource "azurerm_sentinel_alert_rule_scheduled" "potential_meterpreter_cobaltstrike_activity" {
  name                       = "potential_meterpreter_cobaltstrike_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Meterpreter/CobaltStrike Activity"
  description                = "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting - Commandlines containing components like cmd accidentally - Jobs and services started with cmd"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\services.exe" and (((ProcessCommandLine contains "cmd" or ProcessCommandLine contains "%COMSPEC%") and (ProcessCommandLine contains "/c" and ProcessCommandLine contains "echo" and ProcessCommandLine contains "\\pipe\\")) or (ProcessCommandLine contains "rundll32" and ProcessCommandLine contains ".dll,a" and ProcessCommandLine contains "/p:")) and (not(ProcessCommandLine contains "MpCmdRun"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1134"]
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
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}