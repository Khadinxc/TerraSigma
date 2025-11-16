resource "azurerm_sentinel_alert_rule_scheduled" "new_custom_shim_database_created" {
  name                       = "new_custom_shim_database_created"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Custom Shim Database Created"
  description                = "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. - Legitimate custom SHIM installations will also trigger this rule"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains ":\\Windows\\apppatch\\Custom\\" or FolderPath contains ":\\Windows\\apppatch\\CustomSDB\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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