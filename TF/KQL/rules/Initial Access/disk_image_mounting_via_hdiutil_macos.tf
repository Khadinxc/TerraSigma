resource "azurerm_sentinel_alert_rule_scheduled" "disk_image_mounting_via_hdiutil_macos" {
  name                       = "disk_image_mounting_via_hdiutil_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disk Image Mounting Via Hdiutil - MacOS"
  description                = "Detects the execution of the hdiutil utility in order to mount disk images. - Legitimate usage of hdiutil by administrators and users."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "attach " or ProcessCommandLine contains "mount ") and FolderPath endswith "/hdiutil"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Collection"]
  techniques                 = ["T1566", "T1560"]
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