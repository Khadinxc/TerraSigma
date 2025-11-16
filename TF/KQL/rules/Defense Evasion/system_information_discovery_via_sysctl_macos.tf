resource "azurerm_sentinel_alert_rule_scheduled" "system_information_discovery_via_sysctl_macos" {
  name                       = "system_information_discovery_via_sysctl_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Information Discovery Via Sysctl - MacOS"
  description                = "Detects the execution of \"sysctl\" with specific arguments that have been used by threat actors and malware. It provides system hardware information. This process is primarily used to detect and avoid virtualization and analysis environments. - Legitimate administrative activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "hw." or ProcessCommandLine contains "kern." or ProcessCommandLine contains "machdep.") and (FolderPath endswith "/sysctl" or ProcessCommandLine contains "sysctl")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Discovery"]
  techniques                 = ["T1497", "T1082"]
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