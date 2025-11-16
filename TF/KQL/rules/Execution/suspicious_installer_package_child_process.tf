resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_installer_package_child_process" {
  name                       = "suspicious_installer_package_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Installer Package Child Process"
  description                = "Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters - Legitimate software uses the scripts (preinstall, postinstall)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "preinstall" or ProcessCommandLine contains "postinstall") and (FolderPath endswith "/sh" or FolderPath endswith "/bash" or FolderPath endswith "/dash" or FolderPath endswith "/python" or FolderPath endswith "/ruby" or FolderPath endswith "/perl" or FolderPath endswith "/php" or FolderPath endswith "/javascript" or FolderPath endswith "/osascript" or FolderPath endswith "/tclsh" or FolderPath endswith "/curl" or FolderPath endswith "/wget") and (InitiatingProcessFolderPath endswith "/package_script_service" or InitiatingProcessFolderPath endswith "/installer")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "CommandAndControl"]
  techniques                 = ["T1059", "T1071"]
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