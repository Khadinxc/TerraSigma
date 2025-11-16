resource "azurerm_sentinel_alert_rule_scheduled" "arbitrary_shell_command_execution_via_settingcontent_ms" {
  name                       = "arbitrary_shell_command_execution_via_settingcontent_ms"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Arbitrary Shell Command Execution Via Settingcontent-Ms"
  description                = "The .SettingContent-ms file type was introduced in Windows 10 and allows a user to create \"shortcuts\" to various Windows 10 setting pages. These files are simply XML and contain paths to various Windows 10 settings binaries."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains ".SettingContent-ms" and (not(ProcessCommandLine contains "immersivecontrolpanel"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "InitialAccess"]
  techniques                 = ["T1204", "T1566"]
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
  }
}