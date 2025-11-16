resource "azurerm_sentinel_alert_rule_scheduled" "trusted_path_bypass_via_windows_directory_spoofing" {
  name                       = "trusted_path_bypass_via_windows_directory_spoofing"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Trusted Path Bypass via Windows Directory Spoofing"
  description                = "Detects DLLs loading from a spoofed Windows directory path with an extra space (e.g \"C:\\Windows \\System32\") which can bypass Windows trusted path verification. This technique tricks Windows into treating the path as trusted, allowing malicious DLLs to load with high integrity privileges bypassing UAC. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath contains ":\\Windows \\System32\\" or FolderPath contains ":\\Windows \\SysWOW64\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1574", "T1548"]
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