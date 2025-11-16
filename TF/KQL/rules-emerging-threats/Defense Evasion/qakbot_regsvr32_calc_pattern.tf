resource "azurerm_sentinel_alert_rule_scheduled" "qakbot_regsvr32_calc_pattern" {
  name                       = "qakbot_regsvr32_calc_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Qakbot Regsvr32 Calc Pattern"
  description                = "Detects a specific command line of \"regsvr32\" where the \"calc\" keyword is used in conjunction with the \"/s\" flag. This behavior is often seen used by Qakbot - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -s" or ProcessCommandLine contains " /s" or ProcessCommandLine contains " –s" or ProcessCommandLine contains " —s" or ProcessCommandLine contains " ―s") and ProcessCommandLine endswith " calc" and FolderPath endswith "\\regsvr32.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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