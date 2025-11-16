resource "azurerm_sentinel_alert_rule_scheduled" "potential_container_discovery_via_inodes_listing" {
  name                       = "potential_container_discovery_via_inodes_listing"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Container Discovery Via Inodes Listing"
  description                = "Detects listing of the inodes of the \"/\" directory to determine if the we are running inside of a container. - Legitimate system administrator usage of these commands - Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -" and ProcessCommandLine contains "i") and (ProcessCommandLine contains " -" and ProcessCommandLine contains "d")) and ProcessCommandLine endswith " /" and FolderPath endswith "/ls"
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