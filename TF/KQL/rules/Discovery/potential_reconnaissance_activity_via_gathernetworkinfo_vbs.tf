resource "azurerm_sentinel_alert_rule_scheduled" "potential_reconnaissance_activity_via_gathernetworkinfo_vbs" {
  name                       = "potential_reconnaissance_activity_via_gathernetworkinfo_vbs"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Reconnaissance Activity Via GatherNetworkInfo.VBS"
  description                = "Detects execution of the built-in script located in \"C:\\Windows\\System32\\gatherNetworkInfo.vbs\". Which can be used to gather information about the target machine - Administrative activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "gatherNetworkInfo.vbs" and ((FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\wscript.exe") or (ProcessVersionInfoOriginalFileName in~ ("cscript.exe", "wscript.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "Execution"]
  techniques                 = ["T1615", "T1059"]
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