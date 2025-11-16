resource "azurerm_sentinel_alert_rule_scheduled" "capabilities_discovery_linux" {
  name                       = "capabilities_discovery_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Capabilities Discovery - Linux"
  description                = "Detects usage of \"getcap\" binary. This is often used during recon activity to determine potential binaries that can be abused as GTFOBins or other."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -r " or ProcessCommandLine contains " /r " or ProcessCommandLine contains " –r " or ProcessCommandLine contains " —r " or ProcessCommandLine contains " ―r ") and FolderPath endswith "/getcap"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1083"]
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