resource "azurerm_sentinel_alert_rule_scheduled" "mmc_spawning_windows_shell" {
  name                       = "mmc_spawning_windows_shell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "MMC Spawning Windows Shell"
  description                = "Detects a Windows command line executable started from MMC"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\mmc.exe" and ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\regsvr32.exe") or FolderPath contains "\\BITSADMIN")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement"]
  techniques                 = ["T1021"]
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