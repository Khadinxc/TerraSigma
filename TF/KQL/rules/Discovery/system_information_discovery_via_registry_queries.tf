resource "azurerm_sentinel_alert_rule_scheduled" "system_information_discovery_via_registry_queries" {
  name                       = "system_information_discovery_via_registry_queries"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Information Discovery via Registry Queries"
  description                = "Detects attempts to query system information directly from the Windows Registry. - Unlikely"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains "Get-ItemPropertyValue" or ProcessCommandLine contains "gpv") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")) or (ProcessCommandLine contains "query" and (ProcessCommandLine contains "-v" or ProcessCommandLine contains "/v" or ProcessCommandLine contains "–v" or ProcessCommandLine contains "—v" or ProcessCommandLine contains "―v") and FolderPath endswith "\\reg.exe")) and (ProcessCommandLine contains "\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" or ProcessCommandLine contains "\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces" or ProcessCommandLine contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" or ProcessCommandLine contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" or ProcessCommandLine contains "\\SOFTWARE\\Microsoft\\Windows Defender" or ProcessCommandLine contains "\\SYSTEM\\CurrentControlSet\\Services" or ProcessCommandLine contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks")
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