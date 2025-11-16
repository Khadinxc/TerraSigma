resource "azurerm_sentinel_alert_rule_scheduled" "system_information_discovery" {
  name                       = "system_information_discovery"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Information Discovery"
  description                = "Detects system information discovery commands - Legitimate administration activities"
  severity                   = "Informational"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/uname" or FolderPath endswith "/hostname" or FolderPath endswith "/uptime" or FolderPath endswith "/lspci" or FolderPath endswith "/dmidecode" or FolderPath endswith "/lscpu" or FolderPath endswith "/lsmod"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1082"]
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