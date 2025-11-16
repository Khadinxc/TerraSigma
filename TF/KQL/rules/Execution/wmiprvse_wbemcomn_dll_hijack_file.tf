resource "azurerm_sentinel_alert_rule_scheduled" "wmiprvse_wbemcomn_dll_hijack_file" {
  name                       = "wmiprvse_wbemcomn_dll_hijack_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wmiprvse Wbemcomn DLL Hijack - File"
  description                = "Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\\Windows\\System32\\wbem\\` directory over the network and loading it for a WMI DLL Hijack scenario."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath =~ "System" and FolderPath endswith "\\wbem\\wbemcomn.dll"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement"]
  techniques                 = ["T1047", "T1021"]
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