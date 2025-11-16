resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_sysaidserver_child" {
  name                       = "suspicious_sysaidserver_child"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious SysAidServer Child"
  description                = "Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessCommandLine contains "SysAidServer" and (InitiatingProcessFolderPath endswith "\\java.exe" or InitiatingProcessFolderPath endswith "\\javaw.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement"]
  techniques                 = ["T1210"]
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