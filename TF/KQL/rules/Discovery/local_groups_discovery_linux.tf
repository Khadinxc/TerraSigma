resource "azurerm_sentinel_alert_rule_scheduled" "local_groups_discovery_linux" {
  name                       = "local_groups_discovery_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Local Groups Discovery - Linux"
  description                = "Detects enumeration of local system groups. Adversaries may attempt to find local system groups and permission settings - Legitimate administration activities"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/groups" or (ProcessCommandLine contains "/etc/group" and (FolderPath endswith "/cat" or FolderPath endswith "/ed" or FolderPath endswith "/head" or FolderPath endswith "/less" or FolderPath endswith "/more" or FolderPath endswith "/nano" or FolderPath endswith "/tail" or FolderPath endswith "/vi" or FolderPath endswith "/vim"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1069"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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