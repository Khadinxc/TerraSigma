resource "azurerm_sentinel_alert_rule_scheduled" "docker_container_discovery_via_dockerenv_listing" {
  name                       = "docker_container_discovery_via_dockerenv_listing"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Docker Container Discovery Via Dockerenv Listing"
  description                = "Detects listing or file reading of \".dockerenv\" which can be a sing of potential container discovery - Legitimate system administrator usage of these commands - Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine endswith ".dockerenv" and (FolderPath endswith "/cat" or FolderPath endswith "/dir" or FolderPath endswith "/find" or FolderPath endswith "/ls" or FolderPath endswith "/stat" or FolderPath endswith "/test" or FolderPath endswith "grep")
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