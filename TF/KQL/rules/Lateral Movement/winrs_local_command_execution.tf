resource "azurerm_sentinel_alert_rule_scheduled" "winrs_local_command_execution" {
  name                       = "winrs_local_command_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Winrs Local Command Execution"
  description                = "Detects the execution of Winrs.exe where it is used to execute commands locally. Commands executed this way are launched under Winrshost.exe and can represent proxy execution used for defense evasion or lateral movement. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\winrs.exe" or ProcessVersionInfoOriginalFileName =~ "winrs.exe") and (ProcessCommandLine contains "-r:localhost" or ProcessCommandLine contains "/r:localhost" or ProcessCommandLine contains "–r:localhost" or ProcessCommandLine contains "—r:localhost" or ProcessCommandLine contains "―r:localhost" or ProcessCommandLine contains "-r:127.0.0.1" or ProcessCommandLine contains "/r:127.0.0.1" or ProcessCommandLine contains "–r:127.0.0.1" or ProcessCommandLine contains "—r:127.0.0.1" or ProcessCommandLine contains "―r:127.0.0.1" or ProcessCommandLine contains "-r:[::1]" or ProcessCommandLine contains "/r:[::1]" or ProcessCommandLine contains "–r:[::1]" or ProcessCommandLine contains "—r:[::1]" or ProcessCommandLine contains "―r:[::1]" or ProcessCommandLine contains "-remote:localhost" or ProcessCommandLine contains "/remote:localhost" or ProcessCommandLine contains "–remote:localhost" or ProcessCommandLine contains "—remote:localhost" or ProcessCommandLine contains "―remote:localhost" or ProcessCommandLine contains "-remote:127.0.0.1" or ProcessCommandLine contains "/remote:127.0.0.1" or ProcessCommandLine contains "–remote:127.0.0.1" or ProcessCommandLine contains "—remote:127.0.0.1" or ProcessCommandLine contains "―remote:127.0.0.1" or ProcessCommandLine contains "-remote:[::1]" or ProcessCommandLine contains "/remote:[::1]" or ProcessCommandLine contains "–remote:[::1]" or ProcessCommandLine contains "—remote:[::1]" or ProcessCommandLine contains "―remote:[::1]")) or ((FolderPath endswith "\\winrs.exe" or ProcessVersionInfoOriginalFileName =~ "winrs.exe") and (not((ProcessCommandLine contains "-r:" or ProcessCommandLine contains "/r:" or ProcessCommandLine contains "–r:" or ProcessCommandLine contains "—r:" or ProcessCommandLine contains "―r:" or ProcessCommandLine contains "-remote:" or ProcessCommandLine contains "/remote:" or ProcessCommandLine contains "–remote:" or ProcessCommandLine contains "—remote:" or ProcessCommandLine contains "―remote:"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement", "DefenseEvasion"]
  techniques                 = ["T1021", "T1218"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}