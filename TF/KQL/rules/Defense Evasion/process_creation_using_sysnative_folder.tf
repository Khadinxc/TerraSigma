resource "azurerm_sentinel_alert_rule_scheduled" "process_creation_using_sysnative_folder" {
  name                       = "process_creation_using_sysnative_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Creation Using Sysnative Folder"
  description                = "Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ":\\Windows\\Sysnative\\" or FolderPath contains ":\\Windows\\Sysnative\\") and (not((ProcessCommandLine contains "install" and (FolderPath contains "C:\\Windows\\Microsoft.NET\\Framework64\\v" or FolderPath contains "C:\\Windows\\Microsoft.NET\\Framework\\v" or FolderPath contains "C:\\Windows\\Microsoft.NET\\FrameworkArm\\v" or FolderPath contains "C:\\Windows\\Microsoft.NET\\FrameworkArm64\\v") and FolderPath endswith "\\ngen.exe"))) and (not((ProcessCommandLine contains "\"C:\\Windows\\sysnative\\cmd.exe\"" and ProcessCommandLine contains "\\xampp\\" and ProcessCommandLine contains "\\catalina_start.bat")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1055"]
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