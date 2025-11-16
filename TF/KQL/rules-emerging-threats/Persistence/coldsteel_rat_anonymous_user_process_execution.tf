resource "azurerm_sentinel_alert_rule_scheduled" "coldsteel_rat_anonymous_user_process_execution" {
  name                       = "coldsteel_rat_anonymous_user_process_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "COLDSTEEL RAT Anonymous User Process Execution"
  description                = "Detects the creation of a process executing as user called \"ANONYMOUS\" seen used by the \"MileStone2016\" variant of COLDSTEEL"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath contains "\\Windows\\System32\\" or InitiatingProcessFolderPath contains "\\AppData\\") and AccountName contains "ANONYMOUS"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
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