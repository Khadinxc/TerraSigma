resource "azurerm_sentinel_alert_rule_scheduled" "shell_execution_via_find_linux" {
  name                       = "shell_execution_via_find_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shell Execution via Find - Linux"
  description                = "Detects the use of the find command to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or exploitation attempt."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/bin/bash" or ProcessCommandLine contains "/bin/dash" or ProcessCommandLine contains "/bin/fish" or ProcessCommandLine contains "/bin/sh" or ProcessCommandLine contains "/bin/zsh") and ((ProcessCommandLine contains " . " and ProcessCommandLine contains "-exec") and FolderPath endswith "/find")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1083"]
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