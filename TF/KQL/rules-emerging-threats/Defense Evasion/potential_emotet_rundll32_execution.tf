resource "azurerm_sentinel_alert_rule_scheduled" "potential_emotet_rundll32_execution" {
  name                       = "potential_emotet_rundll32_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Emotet Rundll32 Execution"
  description                = "Detecting Emotet DLL loading by looking for rundll32.exe processes with command lines ending in ,RunDLL or ,Control_RunDLL"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine endswith ",RunDLL" or ProcessCommandLine endswith ",Control_RunDLL") and (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE")) and (not((InitiatingProcessFolderPath endswith "\\tracker.exe" or (ProcessCommandLine endswith ".dll,Control_RunDLL" or ProcessCommandLine endswith ".dll\",Control_RunDLL" or ProcessCommandLine endswith ".dll',Control_RunDLL"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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