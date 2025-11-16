resource "azurerm_sentinel_alert_rule_scheduled" "shell_invocation_via_env_command_linux" {
  name                       = "shell_invocation_via_env_command_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shell Invocation via Env Command - Linux"
  description                = "Detects the use of the env command to invoke a shell. This may indicate an attempt to bypass restricted environments, escalate privileges, or execute arbitrary commands. - Github operations such as ghe-backup"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith "/bin/bash" or ProcessCommandLine endswith "/bin/dash" or ProcessCommandLine endswith "/bin/fish" or ProcessCommandLine endswith "/bin/sh" or ProcessCommandLine endswith "/bin/zsh") and FolderPath endswith "/env"
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