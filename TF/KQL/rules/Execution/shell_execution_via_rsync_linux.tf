resource "azurerm_sentinel_alert_rule_scheduled" "shell_execution_via_rsync_linux" {
  name                       = "shell_execution_via_rsync_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shell Execution via Rsync - Linux"
  description                = "Detects the use of the \"rsync\" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments. - Legitimate cases in which \"rsync\" is used to execute a shell"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/ash " or ProcessCommandLine contains "/bash " or ProcessCommandLine contains "/dash " or ProcessCommandLine contains "/csh " or ProcessCommandLine contains "/sh " or ProcessCommandLine contains "/zsh " or ProcessCommandLine contains "/tcsh " or ProcessCommandLine contains "/ksh " or ProcessCommandLine contains "'ash " or ProcessCommandLine contains "'bash " or ProcessCommandLine contains "'dash " or ProcessCommandLine contains "'csh " or ProcessCommandLine contains "'sh " or ProcessCommandLine contains "'zsh " or ProcessCommandLine contains "'tcsh " or ProcessCommandLine contains "'ksh ") and (ProcessCommandLine contains " -e " and (FolderPath endswith "/rsync" or FolderPath endswith "/rsyncd"))
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