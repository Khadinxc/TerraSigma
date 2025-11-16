resource "azurerm_sentinel_alert_rule_scheduled" "os_architecture_discovery_via_grep" {
  name                       = "os_architecture_discovery_via_grep"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OS Architecture Discovery Via Grep"
  description                = "Detects the use of grep to identify information about the operating system architecture. Often combined beforehand with the execution of \"uname\" or \"cat /proc/cpuinfo\""
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith "aarch64" or ProcessCommandLine endswith "arm" or ProcessCommandLine endswith "i386" or ProcessCommandLine endswith "i686" or ProcessCommandLine endswith "mips" or ProcessCommandLine endswith "x86_64") and FolderPath endswith "/grep"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1082"]
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