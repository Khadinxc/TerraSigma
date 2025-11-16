resource "azurerm_sentinel_alert_rule_scheduled" "terminal_service_process_spawn" {
  name                       = "terminal_service_process_spawn"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Terminal Service Process Spawn"
  description                = "Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessCommandLine contains "\\svchost.exe" and InitiatingProcessCommandLine contains "termsvcs") and (not(((FolderPath endswith "\\rdpclip.exe" or FolderPath endswith ":\\Windows\\System32\\csrss.exe" or FolderPath endswith ":\\Windows\\System32\\wininit.exe" or FolderPath endswith ":\\Windows\\System32\\winlogon.exe") or isnull(FolderPath))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "LateralMovement"]
  techniques                 = ["T1190", "T1210"]
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