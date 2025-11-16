resource "azurerm_sentinel_alert_rule_scheduled" "vim_gtfobin_abuse_linux" {
  name                       = "vim_gtfobin_abuse_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Vim GTFOBin Abuse - Linux"
  description                = "Detects the use of \"vim\" and it's siblings commands to execute a shell or proxy commands. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ":!/" or ProcessCommandLine contains ":lua " or ProcessCommandLine contains ":py " or ProcessCommandLine contains "/bin/bash" or ProcessCommandLine contains "/bin/dash" or ProcessCommandLine contains "/bin/fish" or ProcessCommandLine contains "/bin/sh" or ProcessCommandLine contains "/bin/zsh") and ((ProcessCommandLine contains " --cmd" or ProcessCommandLine contains " -c ") and (FolderPath endswith "/rvim" or FolderPath endswith "/vim" or FolderPath endswith "/vimdiff"))
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