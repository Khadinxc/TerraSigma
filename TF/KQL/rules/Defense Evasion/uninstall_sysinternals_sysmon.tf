resource "azurerm_sentinel_alert_rule_scheduled" "uninstall_sysinternals_sysmon" {
  name                       = "uninstall_sysinternals_sysmon"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uninstall Sysinternals Sysmon"
  description                = "Detects the removal of Sysmon, which could be a potential attempt at defense evasion - Legitimate administrators might use this command to remove Sysmon for debugging purposes"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-u" or ProcessCommandLine contains "/u" or ProcessCommandLine contains "–u" or ProcessCommandLine contains "—u" or ProcessCommandLine contains "―u") and ((FolderPath endswith "\\Sysmon64.exe" or FolderPath endswith "\\Sysmon.exe") or ProcessVersionInfoFileDescription =~ "System activity monitor")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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