resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_microsoft_office_add_in" {
  name                       = "potential_persistence_via_microsoft_office_add_in"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Microsoft Office Add-In"
  description                = "Detects potential persistence activity via startup add-ins that load when Microsoft Office starts (.wll/.xll are simply .dll fit for Word or Excel). - Legitimate add-ins"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\Microsoft\\Addins\\" and (FolderPath endswith ".xlam" or FolderPath endswith ".xla" or FolderPath endswith ".ppam")) or (FolderPath contains "\\Microsoft\\Word\\Startup\\" and FolderPath endswith ".wll") or (FolderPath contains "Microsoft\\Excel\\XLSTART\\" and FolderPath endswith ".xlam") or (FolderPath contains "\\Microsoft\\Excel\\Startup\\" and FolderPath endswith ".xll")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1137"]
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