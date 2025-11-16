resource "azurerm_sentinel_alert_rule_scheduled" "potential_dcom_internetexplorer_application_dll_hijack" {
  name                       = "potential_dcom_internetexplorer_application_dll_hijack"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DCOM InternetExplorer.Application DLL Hijack"
  description                = "Detects potential DLL hijack of \"iertutil.dll\" found in the DCOM InternetExplorer.Application Class over the network"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath =~ "System" and FolderPath endswith "\\Internet Explorer\\iertutil.dll"
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