resource "azurerm_sentinel_alert_rule_scheduled" "foggyweb_backdoor_dll_loading" {
  name                       = "foggyweb_backdoor_dll_loading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "FoggyWeb Backdoor DLL Loading"
  description                = "Detects DLL hijacking technique used by NOBELIUM in their FoggyWeb backdoor. Which loads a malicious version of the expected \"version.dll\" dll - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath =~ "C:\\Windows\\ADFS\\version.dll"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1587"]
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