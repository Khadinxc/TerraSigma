resource "azurerm_sentinel_alert_rule_scheduled" "clipboard_collection_with_xclip_tool" {
  name                       = "clipboard_collection_with_xclip_tool"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Clipboard Collection with Xclip Tool"
  description                = "Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed. Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations. - Legitimate usage of xclip tools."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-sel" and ProcessCommandLine contains "clip" and ProcessCommandLine contains "-o") and FolderPath contains "xclip"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1115"]
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