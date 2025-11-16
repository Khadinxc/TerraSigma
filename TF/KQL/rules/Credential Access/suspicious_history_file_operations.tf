resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_history_file_operations" {
  name                       = "suspicious_history_file_operations"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious History File Operations"
  description                = "Detects commandline operations on shell history files - Legitimate administrative activity - Legitimate software, cleaning hist file"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains ".bash_history" or ProcessCommandLine contains ".zsh_history" or ProcessCommandLine contains ".zhistory" or ProcessCommandLine contains ".history" or ProcessCommandLine contains ".sh_history" or ProcessCommandLine contains "fish_history"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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