resource "azurerm_sentinel_alert_rule_scheduled" "process_execution_from_webdav_share" {
  name                       = "process_execution_from_webdav_share"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Execution From WebDAV Share"
  description                = "Detects execution of processes with image paths starting with WebDAV shares (\\\\), which might indicate malicious file execution from remote web shares. Execution of processes from WebDAV shares can be a sign of lateral movement or exploitation attempts, especially if the process is not a known legitimate application. Exploitation Attempt of vulnerabilities like CVE-2025-33053 also involves executing processes from WebDAV paths. - Legitimate use of WebDAV shares for process execution - Known applications executing from WebDAV paths"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath contains "\\DavWWWRoot\\" and FolderPath startswith "\\\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "CommandAndControl", "LateralMovement"]
  techniques                 = ["T1105"]
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