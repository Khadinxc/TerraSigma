resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_deno_file_written_from_remote_source" {
  name                       = "suspicious_deno_file_written_from_remote_source"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Deno File Written from Remote Source"
  description                = "Detects Deno writing a file from a direct HTTP(s) call and writing to the appdata folder or bringing it's own malicious DLL. This behavior may indicate an attempt to execute remotely hosted, potentially malicious files through deno. - Legitimate usage of deno to request a file or bring a DLL to a host"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\deno\\gen\\" or FolderPath contains "\\deno\\remote\\https\\") and (FolderPath contains ":\\Users\\" and FolderPath contains "\\AppData\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "CommandAndControl"]
  techniques                 = ["T1204", "T1059", "T1105"]
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