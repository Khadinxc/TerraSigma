resource "azurerm_sentinel_alert_rule_scheduled" "potential_file_overwrite_via_sysinternals_sdelete" {
  name                       = "potential_file_overwrite_via_sysinternals_sdelete"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential File Overwrite Via Sysinternals SDelete"
  description                = "Detects the use of SDelete to erase a file not the free space"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName =~ "sdelete.exe" and (not((ProcessCommandLine contains " -h" or ProcessCommandLine contains " -c" or ProcessCommandLine contains " -z" or ProcessCommandLine contains " /?")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1485"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
  }
}