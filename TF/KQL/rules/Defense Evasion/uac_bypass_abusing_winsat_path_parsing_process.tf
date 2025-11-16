resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_abusing_winsat_path_parsing_process" {
  name                       = "uac_bypass_abusing_winsat_path_parsing_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Abusing Winsat Path Parsing - Process"
  description                = "Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessIntegrityLevel in~ ("High", "System", "S-1-16-16384", "S-1-16-12288")) and InitiatingProcessCommandLine contains "C:\\Windows \\system32\\winsat.exe" and InitiatingProcessFolderPath endswith "\\AppData\\Local\\Temp\\system32\\winsat.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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