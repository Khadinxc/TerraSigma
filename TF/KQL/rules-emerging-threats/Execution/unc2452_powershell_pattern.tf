resource "azurerm_sentinel_alert_rule_scheduled" "unc2452_powershell_pattern" {
  name                       = "unc2452_powershell_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UNC2452 PowerShell Pattern"
  description                = "Detects a specific PowerShell command line pattern used by the UNC2452 actors as mentioned in Microsoft and Symantec reports - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Invoke-WMIMethod win32_process -name create -argumentlist" and ProcessCommandLine contains "rundll32 c:\\windows") or (ProcessCommandLine contains "wmic /node:" and ProcessCommandLine contains "process call create \"rundll32 c:\\windows")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059", "T1047"]
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