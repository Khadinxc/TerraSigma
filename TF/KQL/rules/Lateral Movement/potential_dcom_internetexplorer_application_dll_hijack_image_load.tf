resource "azurerm_sentinel_alert_rule_scheduled" "potential_dcom_internetexplorer_application_dll_hijack_image_load" {
  name                       = "potential_dcom_internetexplorer_application_dll_hijack_image_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DCOM InternetExplorer.Application DLL Hijack - Image Load"
  description                = "Detects potential DLL hijack of \"iertutil.dll\" found in the DCOM InternetExplorer.Application Class"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\Internet Explorer\\iertutil.dll" and InitiatingProcessFolderPath endswith "\\Internet Explorer\\iexplore.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement"]
  techniques                 = ["T1021"]
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