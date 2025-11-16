resource "azurerm_sentinel_alert_rule_scheduled" "operator_bloopers_cobalt_strike_modules" {
  name                       = "operator_bloopers_cobalt_strike_modules"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Operator Bloopers Cobalt Strike Modules"
  description                = "Detects Cobalt Strike module/commands accidentally entered in CMD shell"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Invoke-UserHunter" or ProcessCommandLine contains "Invoke-ShareFinder" or ProcessCommandLine contains "Invoke-Kerberoast" or ProcessCommandLine contains "Invoke-SMBAutoBrute" or ProcessCommandLine contains "Invoke-Nightmare" or ProcessCommandLine contains "zerologon" or ProcessCommandLine contains "av_query") and (ProcessVersionInfoOriginalFileName =~ "Cmd.Exe" or FolderPath endswith "\\cmd.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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