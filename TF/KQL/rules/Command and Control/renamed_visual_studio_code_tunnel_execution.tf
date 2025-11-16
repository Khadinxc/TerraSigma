resource "azurerm_sentinel_alert_rule_scheduled" "renamed_visual_studio_code_tunnel_execution" {
  name                       = "renamed_visual_studio_code_tunnel_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed Visual Studio Code Tunnel Execution"
  description                = "Detects renamed Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine endswith ".exe tunnel" and isnull(ProcessVersionInfoOriginalFileName)) or (ProcessCommandLine contains ".exe tunnel" and ProcessCommandLine contains "--accept-server-license-terms") or (ProcessCommandLine contains "tunnel " and ProcessCommandLine contains "service" and ProcessCommandLine contains "internal-run" and ProcessCommandLine contains "tunnel-service.log")) and (not((FolderPath endswith "\\code-tunnel.exe" or FolderPath endswith "\\code.exe")))) or (((ProcessCommandLine contains "/d /c " and ProcessCommandLine contains "\\servers\\Stable-" and ProcessCommandLine contains "code-server.cmd") and FolderPath endswith "\\cmd.exe" and InitiatingProcessCommandLine endswith " tunnel") and (not((InitiatingProcessFolderPath endswith "\\code-tunnel.exe" or InitiatingProcessFolderPath endswith "\\code.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1071", "T1219"]
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