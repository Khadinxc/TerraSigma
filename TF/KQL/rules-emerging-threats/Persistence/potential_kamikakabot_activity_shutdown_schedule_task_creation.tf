resource "azurerm_sentinel_alert_rule_scheduled" "potential_kamikakabot_activity_shutdown_schedule_task_creation" {
  name                       = "potential_kamikakabot_activity_shutdown_schedule_task_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential KamiKakaBot Activity - Shutdown Schedule Task Creation"
  description                = "Detects the creation of a schedule task that runs weekly and execute the \"shutdown /l /f\" command. This behavior was observed being used by KamiKakaBot samples in order to achieve persistence on a system."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " /create " and ProcessCommandLine contains "shutdown /l /f" and ProcessCommandLine contains "WEEKLY") and FolderPath endswith "\\schtasks.exe") and (not((AccountName contains "AUTHORI" or AccountName contains "AUTORI")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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