resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_executable_file_creation" {
  name                       = "suspicious_executable_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Executable File Creation"
  description                = "Detect creation of suspicious executable file names. Some strings look for suspicious file extensions, others look for filenames that exploit unquoted service paths."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ":\\$Recycle.Bin.exe" or FolderPath endswith ":\\Documents and Settings.exe" or FolderPath endswith ":\\MSOCache.exe" or FolderPath endswith ":\\PerfLogs.exe" or FolderPath endswith ":\\Recovery.exe" or FolderPath endswith ".bat.exe" or FolderPath endswith ".sys.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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