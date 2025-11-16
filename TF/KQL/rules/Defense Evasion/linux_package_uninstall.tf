resource "azurerm_sentinel_alert_rule_scheduled" "linux_package_uninstall" {
  name                       = "linux_package_uninstall"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Package Uninstall"
  description                = "Detects linux package removal using builtin tools such as \"yum\", \"apt\", \"apt-get\" or \"dpkg\". - Administrator or administrator scripts might delete packages for several reasons (debugging, troubleshooting)."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "remove" or ProcessCommandLine contains "purge") and (FolderPath endswith "/apt" or FolderPath endswith "/apt-get")) or ((ProcessCommandLine contains "--remove " or ProcessCommandLine contains " -r ") and FolderPath endswith "/dpkg") or (ProcessCommandLine contains " -e " and FolderPath endswith "/rpm") or ((ProcessCommandLine contains "erase" or ProcessCommandLine contains "remove") and FolderPath endswith "/yum")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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