resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_attempt_via_run_keys_using_reg_exe" {
  name                       = "potential_persistence_attempt_via_run_keys_using_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Attempt Via Run Keys Using Reg.EXE"
  description                = "Detects suspicious command line reg.exe tool adding key to RUN key in Registry - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reasons. - Legitimate administrator sets up autorun keys for legitimate reasons. - Discord"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Software\\Microsoft\\Windows\\CurrentVersion\\Run" or ProcessCommandLine contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or ProcessCommandLine contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") and (ProcessCommandLine contains "reg" and ProcessCommandLine contains " add ") and FolderPath endswith "\\reg.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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