resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_screensaver_binary_file_creation" {
  name                       = "suspicious_screensaver_binary_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Screensaver Binary File Creation"
  description                = "Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".scr" and (not(((InitiatingProcessFolderPath endswith "\\Kindle.exe" or InitiatingProcessFolderPath endswith "\\Bin\\ccSvcHst.exe") or (InitiatingProcessFolderPath endswith "\\TiWorker.exe" and FolderPath endswith "\\uwfservicingscr.scr"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1546"]
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