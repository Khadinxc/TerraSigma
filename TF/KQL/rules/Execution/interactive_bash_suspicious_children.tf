resource "azurerm_sentinel_alert_rule_scheduled" "interactive_bash_suspicious_children" {
  name                       = "interactive_bash_suspicious_children"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Interactive Bash Suspicious Children"
  description                = "Detects suspicious interactive bash as a parent to rather uncommon child processes - Legitimate software that uses these patterns"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessCommandLine =~ "bash -i" and ((ProcessCommandLine contains "-c import " or ProcessCommandLine contains "base64" or ProcessCommandLine contains "pty.spawn") or (FolderPath endswith "whoami" or FolderPath endswith "iptables" or FolderPath endswith "/ncat" or FolderPath endswith "/nc" or FolderPath endswith "/netcat"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1036"]
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