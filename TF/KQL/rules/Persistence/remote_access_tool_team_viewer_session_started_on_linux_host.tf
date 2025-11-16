resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_team_viewer_session_started_on_linux_host" {
  name                       = "remote_access_tool_team_viewer_session_started_on_linux_host"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - Team Viewer Session Started On Linux Host"
  description                = "Detects the command line executed when TeamViewer starts a session started by a remote host. Once a connection has been started, an investigator can verify the connection details by viewing the \"incoming_connections.txt\" log file in the TeamViewer folder. - Legitimate usage of TeamViewer"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine endswith "/TeamViewer_Desktop --IPCport 5939 --Module 1" and FolderPath endswith "/TeamViewer_Desktop" and InitiatingProcessFolderPath endswith "/TeamViewer_Service"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "InitialAccess"]
  techniques                 = ["T1133"]
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