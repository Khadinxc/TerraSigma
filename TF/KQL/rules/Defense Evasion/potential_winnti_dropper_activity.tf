resource "azurerm_sentinel_alert_rule_scheduled" "potential_winnti_dropper_activity" {
  name                       = "potential_winnti_dropper_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Winnti Dropper Activity"
  description                = "Detects files dropped by Winnti as described in RedMimicry Winnti playbook"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\gthread-3.6.dll" or FolderPath endswith "\\sigcmm-2.4.dll" or FolderPath endswith "\\Windows\\Temp\\tmp.bat"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1027"]
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