resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_renamed_meshagent_execution_macos" {
  name                       = "remote_access_tool_renamed_meshagent_execution_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - Renamed MeshAgent Execution - MacOS"
  description                = "Detects the execution of a renamed instance of the Remote Monitoring and Management (RMM) tool, MeshAgent. RMM tools such as MeshAgent are commonly utilized by IT administrators for legitimate remote support and system management. However, malicious actors may exploit these tools by renaming them to bypass detection mechanisms, enabling unauthorized access and control over compromised systems."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "--meshServiceName" or ProcessVersionInfoOriginalFileName contains "meshagent") and (not((FolderPath endswith "/meshagent" or FolderPath endswith "/meshagent_osx64")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "DefenseEvasion"]
  techniques                 = ["T1219", "T1036"]
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