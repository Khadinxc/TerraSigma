resource "azurerm_sentinel_alert_rule_scheduled" "visual_studio_nodejstools_pressanykey_renamed_execution" {
  name                       = "visual_studio_nodejstools_pressanykey_renamed_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Visual Studio NodejsTools PressAnyKey Renamed Execution"
  description                = "Detects renamed execution of \"Microsoft.NodejsTools.PressAnyKey.exe\", which can be abused as a LOLBIN to execute arbitrary binaries"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName =~ "Microsoft.NodejsTools.PressAnyKey.exe" and (not(FolderPath endswith "\\Microsoft.NodejsTools.PressAnyKey.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}