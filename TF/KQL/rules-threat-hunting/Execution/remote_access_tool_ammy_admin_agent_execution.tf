resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_ammy_admin_agent_execution" {
  name                       = "remote_access_tool_ammy_admin_agent_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - Ammy Admin Agent Execution"
  description                = "Detects the execution of the Ammy Admin RMM agent for remote management. - Legitimate use of Ammy Admin RMM agent for remote management by admins."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "AMMYY\\aa_nts.dll\",run" and FolderPath endswith "\\rundll32.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence"]
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