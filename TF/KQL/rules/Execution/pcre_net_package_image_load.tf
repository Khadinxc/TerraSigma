resource "azurerm_sentinel_alert_rule_scheduled" "pcre_net_package_image_load" {
  name                       = "pcre_net_package_image_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PCRE.NET Package Image Load"
  description                = "Detects processes loading modules related to PCRE.NET package"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath contains "\\AppData\\Local\\Temp\\ba9ea7344a4a5f591d6e5dc32a13494b\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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