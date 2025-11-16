resource "azurerm_sentinel_alert_rule_scheduled" "potential_7za_dll_sideloading" {
  name                       = "potential_7za_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential 7za.DLL Sideloading"
  description                = "Detects potential DLL sideloading of \"7za.dll\" - Legitimate third party application located in \"AppData\" may leverage this DLL to offer 7z compression functionality and may generate false positives. Apply additional filters as needed."
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\7za.dll" and (not(((FolderPath startswith "C:\\Program Files (x86)\\" or FolderPath startswith "C:\\Program Files\\") and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\"))))
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