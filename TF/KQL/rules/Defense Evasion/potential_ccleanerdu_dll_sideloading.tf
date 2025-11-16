resource "azurerm_sentinel_alert_rule_scheduled" "potential_ccleanerdu_dll_sideloading" {
  name                       = "potential_ccleanerdu_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential CCleanerDU.DLL Sideloading"
  description                = "Detects potential DLL sideloading of \"CCleanerDU.dll\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\CCleanerDU.dll" and (not(((InitiatingProcessFolderPath endswith "\\CCleaner.exe" or InitiatingProcessFolderPath endswith "\\CCleaner64.exe") and (InitiatingProcessFolderPath startswith "C:\\Program Files\\CCleaner\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\CCleaner\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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