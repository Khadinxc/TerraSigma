resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_tacticalrmm_agent_registration_to_potentially_attacker_controlled_server" {
  name                       = "remote_access_tool_tacticalrmm_agent_registration_to_potentially_attacker_controlled_server"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - TacticalRMM Agent Registration to Potentially Attacker-Controlled Server"
  description                = "Detects TacticalRMM agent installations where the --api, --auth, and related flags are used on the command line. These parameters configure the agent to connect to a specific RMM server with authentication, client ID, and site ID. This technique could indicate a threat actor attempting to register the agent with an attacker-controlled RMM infrastructure silently. - Legitimate system administrator deploying TacticalRMM"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "--api" and ProcessCommandLine contains "--auth" and ProcessCommandLine contains "--client-id" and ProcessCommandLine contains "--site-id" and ProcessCommandLine contains "--agent-type") and FolderPath contains "\\TacticalAgent\\tacticalrmm.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219", "T1105"]
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