resource "azurerm_sentinel_alert_rule_scheduled" "sysmon_discovery_via_default_driver_altitude_using_findstr_exe" {
  name                       = "sysmon_discovery_via_default_driver_altitude_using_findstr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE"
  description                = "Detects usage of \"findstr\" with the argument \"385201\". Which could indicate potential discovery of an installed Sysinternals Sysmon service using the default driver altitude (even if the name is changed)."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " 385201" and ((FolderPath endswith "\\find.exe" or FolderPath endswith "\\findstr.exe") or (ProcessVersionInfoOriginalFileName in~ ("FIND.EXE", "FINDSTR.EXE")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1518"]
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