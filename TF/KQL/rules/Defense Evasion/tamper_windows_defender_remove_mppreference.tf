resource "azurerm_sentinel_alert_rule_scheduled" "tamper_windows_defender_remove_mppreference" {
  name                       = "tamper_windows_defender_remove_mppreference"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Tamper Windows Defender Remove-MpPreference"
  description                = "Detects attempts to remove Windows Defender configurations using the 'MpPreference' cmdlet - Legitimate PowerShell scripts"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Remove-MpPreference" and (ProcessCommandLine contains "-ControlledFolderAccessProtectedFolders " or ProcessCommandLine contains "-AttackSurfaceReductionRules_Ids " or ProcessCommandLine contains "-AttackSurfaceReductionRules_Actions " or ProcessCommandLine contains "-CheckForSignaturesBeforeRunningScan ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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