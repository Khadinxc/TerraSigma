resource "azurerm_sentinel_alert_rule_scheduled" "hidden_user_creation" {
  name                       = "hidden_user_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Hidden User Creation"
  description                = "Detects creation of a hidden user account on macOS (UserID < 500) or with IsHidden option - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "create" and FolderPath endswith "/dscl") and (ProcessCommandLine contains "UniqueID" and ProcessCommandLine matches regex "([0-9]|[1-9][0-9]|[1-4][0-9]{2})")) or ((ProcessCommandLine contains "create" and FolderPath endswith "/dscl") and (ProcessCommandLine contains "IsHidden" and (ProcessCommandLine contains "true" or ProcessCommandLine contains "yes" or ProcessCommandLine contains "1")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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