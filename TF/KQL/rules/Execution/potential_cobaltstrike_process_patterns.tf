resource "azurerm_sentinel_alert_rule_scheduled" "potential_cobaltstrike_process_patterns" {
  name                       = "potential_cobaltstrike_process_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential CobaltStrike Process Patterns"
  description                = "Detects potential process patterns related to Cobalt Strike beacon activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith "conhost.exe 0xffffffff -ForceV1" and (InitiatingProcessCommandLine contains "cmd.exe /C echo" and InitiatingProcessCommandLine contains " > \\\\.\\pipe")) or (ProcessCommandLine endswith "conhost.exe 0xffffffff -ForceV1" and InitiatingProcessCommandLine endswith "/C whoami") or (ProcessCommandLine endswith "cmd.exe /C whoami" and InitiatingProcessFolderPath startswith "C:\\Temp\\") or ((ProcessCommandLine contains "cmd.exe /c echo" and ProcessCommandLine contains "> \\\\.\\pipe") and (InitiatingProcessFolderPath endswith "\\runonce.exe" or InitiatingProcessFolderPath endswith "\\dllhost.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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