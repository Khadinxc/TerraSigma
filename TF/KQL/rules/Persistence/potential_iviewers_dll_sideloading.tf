resource "azurerm_sentinel_alert_rule_scheduled" "potential_iviewers_dll_sideloading" {
  name                       = "potential_iviewers_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Iviewers.DLL Sideloading"
  description                = "Detects potential DLL sideloading of \"iviewers.dll\" (OLE/COM Object Interface Viewer)"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\iviewers.dll" and (not((FolderPath startswith "C:\\Program Files (x86)\\Windows Kits\\" or FolderPath startswith "C:\\Program Files\\Windows Kits\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
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