resource "azurerm_sentinel_alert_rule_scheduled" "ads_zone_identifier_deleted" {
  name                       = "ads_zone_identifier_deleted"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ADS Zone.Identifier Deleted"
  description                = "Detects the deletion of the \"Zone.Identifier\" ADS. Attackers can leverage this in order to bypass security restrictions that make use of the ADS such as Microsoft Office apps. - Likely"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ":Zone.Identifier"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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