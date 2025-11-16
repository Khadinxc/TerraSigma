resource "azurerm_sentinel_alert_rule_scheduled" "diskshadow_script_mode_execution" {
  name                       = "diskshadow_script_mode_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Diskshadow Script Mode Execution"
  description                = "Detects execution of \"Diskshadow.exe\" in script mode using the \"/s\" flag. Attackers often abuse \"diskshadow\" to execute scripts that deleted the shadow copies on the systems. Investigate the content of the scripts and its location. - Likely from legitimate backup scripts"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-s " or ProcessCommandLine contains "/s " or ProcessCommandLine contains "–s " or ProcessCommandLine contains "—s " or ProcessCommandLine contains "―s ") and (ProcessVersionInfoOriginalFileName =~ "diskshadow.exe" or FolderPath endswith "\\diskshadow.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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