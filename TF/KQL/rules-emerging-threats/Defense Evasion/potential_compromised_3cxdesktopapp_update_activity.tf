resource "azurerm_sentinel_alert_rule_scheduled" "potential_compromised_3cxdesktopapp_update_activity" {
  name                       = "potential_compromised_3cxdesktopapp_update_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Compromised 3CXDesktopApp Update Activity"
  description                = "Detects the 3CXDesktopApp updater downloading a known compromised version of the 3CXDesktopApp software"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "--update" and ProcessCommandLine contains "http" and ProcessCommandLine contains "/electron/update/win32/18.12") and FolderPath endswith "\\3CXDesktopApp\\app\\update.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1218"]
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