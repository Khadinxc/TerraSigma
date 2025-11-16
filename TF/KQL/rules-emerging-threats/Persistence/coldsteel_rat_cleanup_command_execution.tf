resource "azurerm_sentinel_alert_rule_scheduled" "coldsteel_rat_cleanup_command_execution" {
  name                       = "coldsteel_rat_cleanup_command_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "COLDSTEEL RAT Cleanup Command Execution"
  description                = "Detects the creation of a \"rundll32\" process from the ColdSteel persistence service to initiate the cleanup command by calling one of its own exports. This functionality is not present in \"MileStone2017\" and some \"MileStone2016\" samples - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "UpdateDriverForPlugAndPlayDevicesW" or ProcessCommandLine contains "ServiceMain" or ProcessCommandLine contains "DiUninstallDevice") and FolderPath endswith "\\rundll32.exe" and (InitiatingProcessCommandLine contains " -k msupdate" or InitiatingProcessCommandLine contains " -k msupdate2" or InitiatingProcessCommandLine contains " -k alg") and InitiatingProcessFolderPath endswith "\\svchost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
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